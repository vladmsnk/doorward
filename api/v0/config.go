package v0

// Kinds of the configuration documents, as their kind field spells them.
const (
	KindBoundary = "Boundary"
	KindTaskType = "TaskType"
	KindManifest = "Manifest"
)

// Boundary is the most one agent may ever be granted. Metadata.Name is
// the agent's name.
type Boundary struct {
	TypeMeta
	Metadata ObjectMeta   `json:"metadata"`
	Spec     BoundarySpec `json:"spec"`
}

type BoundarySpec struct {
	Owner Owner `json:"owner"`
	// TaskTypes the agent may be started for.
	TaskTypes []string `json:"task_types"`
	// MaxSensitivity is the highest tier of operation the agent may be granted.
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	// MaxTTL caps the lifetime of every grant to the agent.
	MaxTTL      Duration     `json:"max_ttl"`
	Permissions []Permission `json:"permissions"`
	// Limits cap the task type's limits of the same name.
	Limits     []Limit     `json:"limits,omitempty"`
	Delegation *Delegation `json:"delegation,omitempty"`
}

// Owner is who answers for an agent.
type Owner struct {
	Team    string `json:"team"`
	Contact string `json:"contact,omitempty"`
}

// TaskType is a kind of task an application may start. The application
// sends only the type and the object's ID; the scope comes from here.
type TaskType struct {
	TypeMeta
	Metadata ObjectMeta   `json:"metadata"`
	Spec     TaskTypeSpec `json:"spec"`
}

type TaskTypeSpec struct {
	Object TaskObjectSpec `json:"object"`
	// Initiators are the applications allowed to start the task.
	Initiators []string `json:"initiators"`
	// TTL is the lifetime of the root grant, capped by each agent's MaxTTL.
	TTL         Duration     `json:"ttl"`
	Permissions []Permission `json:"permissions"`
	Limits      []Limit      `json:"limits,omitempty"`
	Delegation  *Delegation  `json:"delegation,omitempty"`
}

// TaskObjectSpec says what a task is about.
type TaskObjectSpec struct {
	Type string `json:"type"`
	// IDPattern is an anchored regular expression the object's ID must match.
	IDPattern string `json:"id_pattern"`
}

// Manifest lists the operations one resource exposes through the box's points
// of enforcement, with their tiers and constrainable arguments.
type Manifest struct {
	TypeMeta
	Metadata ObjectMeta   `json:"metadata"`
	Spec     ManifestSpec `json:"spec"`
}

// Protocol is how a resource is called.
type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolMCP  Protocol = "mcp"
)

type ManifestSpec struct {
	Audience   string      `json:"audience"`
	Protocol   Protocol    `json:"protocol"`
	Operations []Operation `json:"operations"`
}

// Operation is one MCP tool or one HTTP route.
type Operation struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Sensitivity Sensitivity `json:"sensitivity"`
	// HTTP is set exactly when the manifest's protocol is http.
	HTTP *HTTPRoute `json:"http,omitempty"`
	// Params are the arguments constraints may refer to, keyed by JSON Pointer.
	Params map[string]Param `json:"params,omitempty"`
}

// HTTPRoute is where an HTTP operation lives.
type HTTPRoute struct {
	Method string `json:"method"`
	// Path is a template; {name} segments are path parameters.
	Path string `json:"path"`
}

// ParamType is the JSON type of an argument.
type ParamType string

const (
	ParamString  ParamType = "string"
	ParamNumber  ParamType = "number"
	ParamInteger ParamType = "integer"
	ParamBoolean ParamType = "boolean"
)

// ParamIn is where an HTTP argument comes from.
type ParamIn string

const (
	ParamInPath  ParamIn = "path"
	ParamInQuery ParamIn = "query"
	ParamInBody  ParamIn = "body"
)

// Param describes one argument.
type Param struct {
	Type ParamType `json:"type"`
	// In is set for HTTP operations only.
	In ParamIn `json:"in,omitempty"`
}
