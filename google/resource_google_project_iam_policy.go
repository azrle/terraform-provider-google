package google

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"google.golang.org/api/cloudresourcemanager/v1"
)

func resourceGoogleProjectIamPolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceGoogleProjectIamPolicyCreate,
		Read:   resourceGoogleProjectIamPolicyRead,
		Update: resourceGoogleProjectIamPolicyUpdate,
		Delete: resourceGoogleProjectIamPolicyDelete,

		Schema: map[string]*schema.Schema{
			"project": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"policy_data": &schema.Schema{
				Type:             schema.TypeString,
				Required:         true,
				DiffSuppressFunc: jsonPolicyDiffSuppress,
			},
			"etag": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceGoogleProjectIamPolicyCreate(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*Config)
	pid := d.Get("project").(string)
	// Get the policy in the template
	p, err := getResourceIamPolicy(d)
	if err != nil {
		return fmt.Errorf("Could not get valid 'policy_data' from resource: %v", err)
	}

	log.Printf("[DEBUG] Setting IAM policy for project %q", pid)
	ep, err := getProjectIamPolicy(pid, config)
	if err != nil {
		return err
	}

	// Merge the policies together
	mb := mergeBindings(append(p.Bindings, getGoogleBindings(pid, ep)...))
	ep.Bindings = mb
	if err = setProjectIamPolicy(ep, config, pid); err != nil {
		return fmt.Errorf("Error applying IAM policy to project: %v", err)
	}

	d.SetId(pid)
	return resourceGoogleProjectIamPolicyRead(d, meta)
}

func resourceGoogleProjectIamPolicyRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG]: Reading google_project_iam_policy")
	config := meta.(*Config)
	pid := d.Get("project").(string)

	p, err := getProjectIamPolicy(pid, config)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG]: Setting etag=%s", p.Etag)
	d.Set("etag", p.Etag)

	// remove bindings managed by Google
	p = subtractIamPolicy(p, &cloudresourcemanager.Policy{Bindings: getGoogleBindings(pid, p)})
	// we only marshal the bindings, because only the bindings get set in the config
	pBytes, err := json.Marshal(&cloudresourcemanager.Policy{Bindings: p.Bindings})
	if err != nil {
		return fmt.Errorf("Error marshaling IAM policy: %v", err)
	}
	log.Printf("[DEBUG]: Setting policy_data=%s", string(pBytes))
	d.Set("policy_data", string(pBytes))
	return nil
}

func resourceGoogleProjectIamPolicyUpdate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG]: Updating google_project_iam_policy")
	config := meta.(*Config)
	pid := d.Get("project").(string)

	// Get the policy in the template
	p, err := getResourceIamPolicy(d)
	if err != nil {
		return fmt.Errorf("Could not get valid 'policy_data' from resource: %v", err)
	}
	pBytes, _ := json.Marshal(p)
	log.Printf("[DEBUG] Got policy from config: %s", string(pBytes))

	log.Printf("[DEBUG] Updating IAM policy for project %q", pid)
	// Get the existing IAM policy from the API
	ep, err := getProjectIamPolicy(pid, config)
	if err != nil {
		return fmt.Errorf("Error retrieving IAM policy from project API: %v", err)
	}
	epBytes, _ := json.Marshal(ep)
	log.Printf("[DEBUG] Got existing version of changed IAM policy from project API: %s", string(epBytes))

	// Merge the policies together
	mb := mergeBindings(append(p.Bindings, getGoogleBindings(pid, ep)...))
	ep.Bindings = mb
	if err = setProjectIamPolicy(ep, config, pid); err != nil {
		return fmt.Errorf("Error applying IAM policy to project: %v", err)
	}

	return resourceGoogleProjectIamPolicyRead(d, meta)
}

func resourceGoogleProjectIamPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG]: Deleting google_project_iam_policy")
	config := meta.(*Config)
	pid := d.Get("project").(string)

	// Get the policy in the template
	pp, err := getPrevResourceIamPolicy(d)
	if err != nil {
		return fmt.Errorf("Could not get valid 'policy_data' from resource: %v", err)
	}
	// Get the existing IAM policy from the API
	ep, err := getProjectIamPolicy(pid, config)
	if err != nil {
		return fmt.Errorf("Error retrieving IAM policy from project API: %v", err)
	}
	if err = setProjectIamPolicy(subtractIamPolicy(ep, pp), config, pid); err != nil {
		return fmt.Errorf("Error applying IAM policy to project: %v", err)
	}
	d.SetId("")
	return nil
}

// Check if a member (email string) is managed by Google
func isManagedByGoogle(project, m string) bool {
	split := strings.Split(m, "@")
	if len(split) != 2 {
		// it is not like an email address
		// definitely not an account managed by google
		return false
	}
	domain := split[1]
	split = strings.Split(domain, ".")
	if len(split) >= 3 &&
		split[len(split)-2] == "gserviceaccount" && split[len(split)-1] == "com" &&
		split[0] != project {
		// accounts managed by google should have domains look like
		// **.gserviceaccount.com
		// and not starting with [PROJECT_ID]
		return true
	}
	return false
}

// Find bindings managed by Google
func getGoogleBindings(project string, p *cloudresourcemanager.Policy) (bindings []*cloudresourcemanager.Binding) {
	for _, binding := range p.Bindings {
		var members []string
		for _, member := range binding.Members {
			if isManagedByGoogle(project, member) {
				members = append(members, member)
			}
		}
		if len(members) > 0 {
			log.Printf("[DEBUG] Find a binding managed by Google: role=%s, members=%v", binding.Role, members)
			bindings = append(bindings, &cloudresourcemanager.Binding{
				Role:    binding.Role,
				Members: members,
			})
		}
	}
	return
}

// Subtract all bindings in policy b from policy a, and return the result
func subtractIamPolicy(a, b *cloudresourcemanager.Policy) *cloudresourcemanager.Policy {
	am := rolesToMembersMap(a.Bindings)

	for _, b := range b.Bindings {
		if _, ok := am[b.Role]; ok {
			for _, m := range b.Members {
				delete(am[b.Role], m)
			}
			if len(am[b.Role]) == 0 {
				delete(am, b.Role)
			}
		}
	}
	a.Bindings = rolesToMembersBinding(am)
	return a
}

func setProjectIamPolicy(policy *cloudresourcemanager.Policy, config *Config, pid string) error {
	// Apply the policy
	pbytes, _ := json.Marshal(policy)
	log.Printf("[DEBUG] Setting policy %#v for project: %s", string(pbytes), pid)
	_, err := config.clientResourceManager.Projects.SetIamPolicy(pid,
		&cloudresourcemanager.SetIamPolicyRequest{Policy: policy}).Do()

	if err != nil {
		return fmt.Errorf("Error applying IAM policy for project %q. Policy is %#v, error is %s", pid, policy, err)
	}
	return nil
}

// Get a cloudresourcemanager.Policy from a schema.ResourceData
func getResourceIamPolicy(d *schema.ResourceData) (*cloudresourcemanager.Policy, error) {
	ps := d.Get("policy_data").(string)
	// The policy string is just a marshaled cloudresourcemanager.Policy.
	policy := &cloudresourcemanager.Policy{}
	if err := json.Unmarshal([]byte(ps), policy); err != nil {
		return nil, fmt.Errorf("Could not unmarshal %s:\n: %v", ps, err)
	}
	return policy, nil
}

// Get the previous cloudresourcemanager.Policy from a schema.ResourceData if the
// resource has changed
func getPrevResourceIamPolicy(d *schema.ResourceData) (*cloudresourcemanager.Policy, error) {
	var policy *cloudresourcemanager.Policy = &cloudresourcemanager.Policy{}
	if d.HasChange("policy_data") {
		v, _ := d.GetChange("policy_data")
		if err := json.Unmarshal([]byte(v.(string)), policy); err != nil {
			return nil, fmt.Errorf("Could not unmarshal previous policy %s:\n: %v", v, err)
		}
	}
	return policy, nil
}

// Retrieve the existing IAM Policy for a Project
func getProjectIamPolicy(project string, config *Config) (*cloudresourcemanager.Policy, error) {
	p, err := config.clientResourceManager.Projects.GetIamPolicy(project,
		&cloudresourcemanager.GetIamPolicyRequest{}).Do()

	if err != nil {
		return nil, fmt.Errorf("Error retrieving IAM policy for project %q: %s", project, err)
	}
	return p, nil
}

// Convert a map of roles->members to a list of Binding
func rolesToMembersBinding(m map[string]map[string]bool) []*cloudresourcemanager.Binding {
	bindings := make([]*cloudresourcemanager.Binding, 0)
	for role, members := range m {
		b := cloudresourcemanager.Binding{
			Role:    role,
			Members: make([]string, 0),
		}
		for m, _ := range members {
			b.Members = append(b.Members, m)
		}
		bindings = append(bindings, &b)
	}
	return bindings
}

// Map a role to a map of members, allowing easy merging of multiple bindings.
func rolesToMembersMap(bindings []*cloudresourcemanager.Binding) map[string]map[string]bool {
	bm := make(map[string]map[string]bool)
	// Get each binding
	for _, b := range bindings {
		// Initialize members map
		if _, ok := bm[b.Role]; !ok {
			bm[b.Role] = make(map[string]bool)
		}
		// Get each member (user/principal) for the binding
		for _, m := range b.Members {
			// Add the member
			bm[b.Role][m] = true
		}
	}
	return bm
}

// Merge multiple Bindings such that Bindings with the same Role result in
// a single Binding with combined Members
func mergeBindings(bindings []*cloudresourcemanager.Binding) []*cloudresourcemanager.Binding {
	bm := rolesToMembersMap(bindings)
	rb := make([]*cloudresourcemanager.Binding, 0)

	for role, members := range bm {
		var b cloudresourcemanager.Binding
		b.Role = role
		b.Members = make([]string, 0)
		for m, _ := range members {
			b.Members = append(b.Members, m)
		}
		rb = append(rb, &b)
	}

	return rb
}

func jsonPolicyDiffSuppress(k, old, new string, d *schema.ResourceData) bool {
	var oldPolicy, newPolicy cloudresourcemanager.Policy
	if err := json.Unmarshal([]byte(old), &oldPolicy); err != nil {
		log.Printf("[ERROR] Could not unmarshal old policy %s: %v", old, err)
		return false
	}
	if err := json.Unmarshal([]byte(new), &newPolicy); err != nil {
		log.Printf("[ERROR] Could not unmarshal new policy %s: %v", new, err)
		return false
	}
	oldPolicy.Bindings = mergeBindings(oldPolicy.Bindings)
	newPolicy.Bindings = mergeBindings(newPolicy.Bindings)
	if newPolicy.Etag != oldPolicy.Etag {
		return false
	}
	if newPolicy.Version != oldPolicy.Version {
		return false
	}
	if len(newPolicy.Bindings) != len(oldPolicy.Bindings) {
		return false
	}
	sort.Sort(sortableBindings(newPolicy.Bindings))
	sort.Sort(sortableBindings(oldPolicy.Bindings))
	for pos, newBinding := range newPolicy.Bindings {
		oldBinding := oldPolicy.Bindings[pos]
		if oldBinding.Role != newBinding.Role {
			return false
		}
		if len(oldBinding.Members) != len(newBinding.Members) {
			return false
		}
		sort.Strings(oldBinding.Members)
		sort.Strings(newBinding.Members)
		for i, newMember := range newBinding.Members {
			oldMember := oldBinding.Members[i]
			if newMember != oldMember {
				return false
			}
		}
	}
	return true
}

type sortableBindings []*cloudresourcemanager.Binding

func (b sortableBindings) Len() int {
	return len(b)
}
func (b sortableBindings) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}
func (b sortableBindings) Less(i, j int) bool {
	return b[i].Role < b[j].Role
}
