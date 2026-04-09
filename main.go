package sync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// Driver for internal Syft/SQLite needs
	_ "github.com/glebarez/go-sqlite"

	// Google Cloud Logging & Audit Protos
	"cloud.google.com/go/logging/logadmin"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"google.golang.org/api/iterator"
	"google.golang.org/genproto/googleapis/cloud/audit"

	// Git Metadata Extraction
	"github.com/go-git/go-git/v5"

	// SBOM Generation
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"

	// Registry & OCI
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/ortelius/ortelius/v12/model"
)

// GitDetails represents metadata extracted from OCI image labels
type GitDetails struct {
	Authors  string `json:"authors,omitempty"`
	Licenses string `json:"licenses,omitempty"`
	RefName  string `json:"ref_name,omitempty"`
	Revision string `json:"revision,omitempty"`
	Source   string `json:"source,omitempty"`
	Title    string `json:"title,omitempty"`
	URL      string `json:"url,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Version  string `json:"version,omitempty"`
}

var (
	BaseURL         = getEnv("DEPLOYHUB_URL", "https://app.deployhub.com")
	SyncAPIURL      = BaseURL + "/api/v1/sync"
	ProjectID       = os.Getenv("GCP_PROJECT")
	LookbackMinutes = getEnvInt("LOOKBACK_MINUTES", 30)
	DryRun          = getEnvBool("DRY_RUN", false)

	// Load ORG mappings at cold start
	OrgMappings = loadOrgMappings()
)

func init() {
	functions.HTTP("SyncDeployments", SyncDeploymentsHandler)
}

type Deployment struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Image     string `json:"image"`
	Tag       string `json:"tag"`
	FullRef   string `json:"full_ref"`
	Timestamp string `json:"timestamp"`
}

// --- Main Handler ---

func SyncDeploymentsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now().UTC().Add(time.Duration(-LookbackMinutes) * time.Minute)
	lastTimestamp := startTime.Format(time.RFC3339)

	log.Printf("[gke2release] Syncing deployments since %s", lastTimestamp)

	deployments, _, err := fetchGKEAuditLogs(ctx, lastTimestamp)
	if err != nil {
		log.Printf("[ERROR] Log fetch failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(deployments) > 0 {
		processBatchSync(ctx, deployments)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Processed %d deployments", len(deployments))
}

// --- Log Scraping Logic ---

func fetchGKEAuditLogs(ctx context.Context, lastTs string) ([]Deployment, string, error) {
	adminClient, err := logadmin.NewClient(ctx, ProjectID)
	if err != nil {
		return nil, "", err
	}
	defer adminClient.Close()

	logFilter := fmt.Sprintf(`
		resource.type="k8s_cluster"
		logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity"
		protoPayload.methodName="io.k8s.core.v1.pods.create"
		timestamp >= "%s"
	`, ProjectID, lastTs)

	var deployments []Deployment
	newLastTs := lastTs

	it := adminClient.Entries(ctx, logadmin.Filter(logFilter))
	for {
		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, "", err
		}

		payload, ok := entry.Payload.(*audit.AuditLog)
		if !ok {
			continue
		}

		var respData, reqData map[string]interface{}
		if payload.Response != nil {
			respData = payload.Response.AsMap()
		}
		if payload.Request != nil {
			reqData = payload.Request.AsMap()
		}

		metadata, _ := respData["metadata"].(map[string]interface{})
		if metadata == nil {
			metadata, _ = reqData["metadata"].(map[string]interface{})
		}
		if metadata == nil {
			continue
		}

		namespace, _ := metadata["namespace"].(string)
		if namespace == "" {
			namespace = "default"
		}
		deployedAt, _ := metadata["creationTimestamp"].(string)
		if deployedAt == "" {
			deployedAt = entry.Timestamp.Format(time.RFC3339)
		}

		spec, _ := respData["spec"].(map[string]interface{})
		if spec == nil {
			spec, _ = reqData["spec"].(map[string]interface{})
		}
		if spec == nil {
			continue
		}

		containers, _ := spec["containers"].([]interface{})
		for _, c := range containers {
			container, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			imageFull, _ := container["image"].(string)
			if imageFull == "" {
				continue
			}

			var image, tag string
			cleanRef := imageFull

			if strings.Contains(imageFull, "@") {
				parts := strings.Split(imageFull, "@")
				if !strings.Contains(parts[1], ":") || len(strings.Split(parts[1], ":")[1]) < 64 {
					cleanRef = parts[0]
				}
				imagePart := parts[0]
				if strings.Contains(imagePart, ":") {
					sub := strings.Split(imagePart, ":")
					image = sub[0]
					tag = sub[1]
				} else {
					image = imagePart
					tag = "latest"
				}
			} else if strings.Contains(imageFull, ":") {
				parts := strings.Split(imageFull, ":")
				image = parts[0]
				tag = parts[1]
			} else {
				image = imageFull
				tag = "latest"
			}

			deployments = append(deployments, Deployment{
				Cluster:   entry.Resource.Labels["cluster_name"],
				Namespace: namespace,
				Image:     image,
				Tag:       tag,
				FullRef:   cleanRef,
				Timestamp: deployedAt,
			})
		}
		newLastTs = entry.Timestamp.Format(time.RFC3339)
	}
	return deduplicateDeployments(deployments), newLastTs, nil
}

// --- Sync Coordination ---

func processBatchSync(ctx context.Context, deployments []Deployment) {
	grouped := make(map[string][]Deployment)
	for _, d := range deployments {
		key := fmt.Sprintf("%s/%s", d.Cluster, d.Namespace)
		grouped[key] = append(grouped[key], d)
	}

	for endpointName, group := range grouped {
		log.Printf("[PROCESS] Starting batch for Endpoint: %s (%d deployments)", endpointName, len(group))

		// Apply org mapping, fall back to namespace if not found
		org := OrgMappings[endpointName]
		if org == "" {
			if len(group) > 0 {
				org = group[0].Namespace
			}
			log.Printf("[WARN] No org mapping found for %s, defaulting to namespace: %s", endpointName, org)
		}

		var syncs []model.ReleaseSync
		for _, d := range group {
			imageRef := d.FullRef
			log.Printf("  -> Processing Image: %s", imageRef)

			ref, err := name.ParseReference(imageRef)
			if err != nil {
				log.Printf("     [!] Reference Parse Error: %v", err)
				continue
			}

			rel := model.NewProjectRelease()
			compName := getReleaseName(d.Image)

			rel.Name = compName
			rel.Version = d.Tag
			rel.DockerRepo = d.Image
			rel.DockerTag = d.Tag

			desc, err := remote.Get(ref)
			if err == nil && desc != nil {
				rel.DockerSha = desc.Digest.String()
				rel.ContentSha = desc.Digest.String()
				log.Printf("     [*] Resolved SHA: %s", rel.DockerSha)
			}

			gitDetails, err := extractImageLabels(imageRef)
			if err == nil && gitDetails != nil && gitDetails.Source != "" {
				log.Printf("     [*] Found Git Source: %s", gitDetails.Source)
				gitMap, gerr := deriveGitValues(ctx, gitDetails.Source, gitDetails.Revision)
				if gerr == nil {
					mapGitToRelease(rel, gitMap)
					log.Printf("     [*] Git Metadata Extracted (Commit: %s)", rel.GitCommit)
				}
			}

			content, err := extractSBOMFromCosignAttestation(ref)
			if err == nil && len(content) > 0 {
				log.Printf("     [*] Attestation found; extracting SBOM")
			} else {
				log.Printf("     [*] No attestation; generating SBOM via Syft...")
				content, _ = generateSBOMFromImage(ctx, imageRef)
			}

			if len(content) > 0 {
				log.Printf("     [+] SBOM successfully attached (%d bytes)", len(content))
				sbom := model.NewSBOM()
				sbom.Content = json.RawMessage(content)
				syncs = append(syncs, model.ReleaseSync{Release: *rel, SBOM: sbom})
			} else {
				log.Printf("     [-] Proceeding without SBOM")
				syncs = append(syncs, model.ReleaseSync{Release: *rel})
			}
		}

		if len(syncs) > 0 {
			endpt := model.Endpoint{}
			endpt.Name = endpointName
			endpt.Org = org
			endpt.EndpointType = model.EndpointType("3") // Cluster type
			endpt.Environment = org                      // Org mapping or namespace fallback

			if endpt.ObjType == "" {
				endpt.ObjType = "Endpoint"
			}

			reqBody := model.SyncWithEndpoint{
				Releases:     syncs,
				EndpointName: endpointName,
				Endpoint:     endpt,
			}

			jsonData, _ := json.MarshalIndent(reqBody, "", "  ")

			if DryRun {
				log.Printf("[DRY-RUN] Sync suppressed. Full JSON payload for %s:\n%s", endpointName, string(jsonData))
				continue
			}

			log.Printf("[INFO] Sending %d processed releases to %s", len(syncs), SyncAPIURL)
			resp, err := http.Post(SyncAPIURL, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("[ERROR] Post failed: %v", err)
			} else {
				log.Printf("[INFO] API Status: %s", resp.Status)
				if resp.StatusCode >= 400 {
					body, _ := io.ReadAll(resp.Body)
					log.Printf("[ERROR] Backend Error Body: %s", string(body))
				}
				resp.Body.Close()
			}
		}
	}
}

// --- SBOM & Metadata Helpers ---

func generateSBOMFromImage(ctx context.Context, imageRef string) ([]byte, error) {
	src, err := syft.GetSource(ctx, imageRef, nil)
	if err != nil || src == nil {
		return nil, err
	}
	defer src.Close()
	sbomResult, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil || sbomResult == nil {
		return nil, err
	}
	enc, _ := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	var buf bytes.Buffer
	_ = enc.Encode(&buf, *sbomResult)
	dirs, _ := filepath.Glob("/tmp/stereoscope*")
	for _, d := range dirs {
		os.RemoveAll(d)
	}
	return buf.Bytes(), nil
}

func deriveGitValues(ctx context.Context, gitURL, commitSha string) (map[string]string, error) {
	tempDir, err := os.MkdirTemp("", "git-clone-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)
	repo, err := git.PlainCloneContext(ctx, tempDir, false, &git.CloneOptions{URL: gitURL, Depth: 0})
	if err != nil {
		return nil, err
	}
	mapping := map[string]string{"GitUrl": gitURL, "GitCommit": commitSha}
	head, _ := repo.Head()
	if head != nil {
		commit, _ := repo.CommitObject(head.Hash())
		if commit != nil {
			mapping["GitBranch"] = head.Name().Short()
			mapping["GitCommitTimestamp"] = commit.Author.When.Format(time.RFC3339)
		}
	}
	return mapping, nil
}

func extractSBOMFromCosignAttestation(ref name.Reference) ([]byte, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	refDigest := ref.Context().Digest(desc.Digest.String())
	idx, err := remote.Referrers(refDigest)
	if err != nil {
		return nil, err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, d := range manifest.Manifests {
		artType := d.ArtifactType
		if artType == "" {
			artType = string(d.MediaType)
		}
		if !strings.Contains(strings.ToLower(artType), "attestation") {
			continue
		}
		refDig, _ := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), d.Digest.String()))
		img, _ := remote.Image(refDig)
		layers, _ := img.Layers()
		for _, layer := range layers {
			rc, _ := layer.Uncompressed()
			content, _ := io.ReadAll(rc)
			rc.Close()
			var env struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(content, &env); err == nil {
				decoded, _ := base64.StdEncoding.DecodeString(env.Payload)
				var stmt map[string]interface{}
				if err := json.Unmarshal(decoded, &stmt); err == nil {
					if pred, ok := stmt["predicate"].(map[string]interface{}); ok {
						return json.Marshal(pred)
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("none")
}

// --- Utilities ---

func loadOrgMappings() map[string]string {
	mappings := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if !strings.HasPrefix(key, "ORG_") {
			continue
		}
		encoded := strings.TrimPrefix(key, "ORG_")
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		decodedBytes, err := base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			log.Printf("[WARN] Invalid ORG_ key encoding: %s", key)
			continue
		}
		mappings[string(decodedBytes)] = value
	}
	return mappings
}

func mapGitToRelease(rel *model.ProjectRelease, m map[string]string) {
	rel.GitCommit = m["GitCommit"]
	rel.GitURL = m["GitUrl"]
	rel.GitBranch = m["GitBranch"]
	if ts, err := time.Parse(time.RFC3339, m["GitCommitTimestamp"]); err == nil {
		rel.GitCommitTimestamp = ts
	}
}

func extractImageLabels(imageRef string) (*GitDetails, error) {
	ref, _ := name.ParseReference(imageRef)
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	img, _ := desc.Image()
	if img == nil {
		return nil, nil
	}
	cfg, _ := img.ConfigFile()
	labels := cfg.Config.Labels
	return &GitDetails{
		Revision: labels["org.opencontainers.image.revision"],
		Source:   labels["org.opencontainers.image.source"],
		URL:      labels["org.opencontainers.image.url"],
	}, nil
}

func getReleaseName(image string) string {
	parts := strings.Split(image, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return image
}

func deduplicateDeployments(deployments []Deployment) []Deployment {
	seen := make(map[string]bool)
	var unique []Deployment
	for _, d := range deployments {
		key := fmt.Sprintf("%s:%s:%s:%s", d.Cluster, d.Namespace, d.Image, d.Tag)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, d)
		}
	}
	return unique
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
