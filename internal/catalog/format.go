package catalog

// FormatVersion is the version of the embedded catalog file format.
const FormatVersion = 1

// File is the JSON document stored (gzip-compressed) in data/catalog.json.gz.
// tools/gen-catalog writes it; this package reads it. Every list is sorted so
// the file is deterministic for the same input.
type File struct {
	FormatVersion int           `json:"format_version"`
	Source        string        `json:"source"`
	Generated     string        `json:"generated"` // YYYY-MM-DD (UTC) of the download
	Services      []FileService `json:"services"`
}

// FileService is one service prefix of the service reference.
type FileService struct {
	Prefix    string         `json:"prefix"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`  // service reference schema version, e.g. "v1.5"
	Modified  int64          `json:"modified"` // Unix time from the reference index
	Actions   []FileAction   `json:"actions"`
	Resources []FileResource `json:"resources,omitempty"`
}

// FileAction is one IAM action and the resource types it authorizes.
type FileAction struct {
	Name      string      `json:"name"`
	Access    AccessLevel `json:"access"`
	Resources []string    `json:"resources,omitempty"`
}

// FileResource is a resource type and its ARN formats.
type FileResource struct {
	Name       string   `json:"name"`
	ARNFormats []string `json:"arn_formats,omitempty"`
}

// AccessLevel classifies an action for tiers and blast radius.
type AccessLevel string

// Access levels, from the service reference annotations (see
// AccessFromAnnotations for the precedence).
const (
	PermissionManagement AccessLevel = "permission_management"
	Tagging              AccessLevel = "tagging"
	Write                AccessLevel = "write"
	List                 AccessLevel = "list"
	Read                 AccessLevel = "read"
)

// AccessFromAnnotations maps the boolean annotations of the service
// reference to one level. They are not mutually exclusive, so the most
// security-relevant one wins: permission management, then tagging-only,
// then write, then list. An action with none set only reads (for example
// s3:GetBucketPolicy).
func AccessFromAnnotations(permissionManagement, taggingOnly, write, list bool) AccessLevel {
	switch {
	case permissionManagement:
		return PermissionManagement
	case taggingOnly:
		return Tagging
	case write:
		return Write
	case list:
		return List
	default:
		return Read
	}
}
