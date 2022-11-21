package main

import (
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/open-policy-agent/opa/ast"
)

const exampleCode = `package test
import future.keywords.if
import future.keywords.in

allow if "admin" in input.roles
`

var tpl = template.Must(template.New("main").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8"/>
		<link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.classless.min.css">
		<script src="https://unpkg.com/htmx.org@1.8.4" integrity="sha384-wg5Y/JwF7VxGk4zLsJEcAojRtlVp1FKKdGy1qN+OMtdq72WRvX/EdRdqg/LOhYeV" crossorigin="anonymous"></script>
	<body>
		<main>
			<pre><textarea name="code"
			  hx-get="/?tmpl=output"
			  hx-trigger="keyup changed delay:500ms"
			  hx-target="#output"
			  style="height: 200px; margin-bottom: 0"
			>{{ .Code }}</textarea></pre>
			{{ block "output" . }}
			<div id="output">
			{{ block "stages" . }}
			<select name="stage"
			  id="stages"
			  size=10
			  hx-get="/result?tmpl=result&code={{ .Code | urlquery }}"
			  hx-target="#result"
			  hx-swap="outerHTML"
			>
				{{ range .Result }}
				<option value="{{ .Stage }}">{{ .Stage }}</option>
				{{ end }}
			</select>
			{{ end }}
			{{ block "result" . }}
			<pre id="result"><code>{{ .Selected }}</code></pre>
			{{ end }}
			</div>
			{{ end }}
		</main>
	</body>
</html>
`))

type CompileResult struct {
	Stage  string
	Result *ast.Module
	Error  string
}

type state struct {
	Code     string
	Selected string
	Result   []CompileResult
}

type stage struct{ name, metricName string }

// NOTE(sr): copied from 0.46.1
var stages []stage = []stage{
	{"ResolveRefs", "compile_stage_resolve_refs"},
	{"InitLocalVarGen", "compile_stage_init_local_var_gen"},
	{"RewriteRuleHeadRefs", "compile_stage_rewrite_rule_head_refs"},
	{"CheckKeywordOverrides", "compile_stage_check_keyword_overrides"},
	{"CheckDuplicateImports", "compile_stage_check_duplicate_imports"},
	{"RemoveImports", "compile_stage_remove_imports"},
	{"SetModuleTree", "compile_stage_set_module_tree"},
	{"SetRuleTree", "compile_stage_set_rule_tree"}, // depends on RewriteRuleHeadRefs
	{"RewriteLocalVars", "compile_stage_rewrite_local_vars"},
	{"CheckVoidCalls", "compile_stage_check_void_calls"},
	{"RewritePrintCalls", "compile_stage_rewrite_print_calls"},
	{"RewriteExprTerms", "compile_stage_rewrite_expr_terms"},
	{"ParseMetadataBlocks", "compile_stage_parse_metadata_blocks"},
	{"SetAnnotationSet", "compile_stage_set_annotationset"},
	{"RewriteRegoMetadataCalls", "compile_stage_rewrite_rego_metadata_calls"},
	{"SetGraph", "compile_stage_set_graph"},
	{"RewriteComprehensionTerms", "compile_stage_rewrite_comprehension_terms"},
	{"RewriteRefsInHead", "compile_stage_rewrite_refs_in_head"},
	{"RewriteWithValues", "compile_stage_rewrite_with_values"},
	{"CheckRuleConflicts", "compile_stage_check_rule_conflicts"},
	{"CheckUndefinedFuncs", "compile_stage_check_undefined_funcs"},
	{"CheckSafetyRuleHeads", "compile_stage_check_safety_rule_heads"},
	{"CheckSafetyRuleBodies", "compile_stage_check_safety_rule_bodies"},
	{"RewriteEquals", "compile_stage_rewrite_equals"},
	{"RewriteDynamicTerms", "compile_stage_rewrite_dynamic_terms"},
	{"CheckRecursion", "compile_stage_check_recursion"},
	{"CheckTypes", "compile_stage_check_types"}, // must be run after CheckRecursion
	{"CheckUnsafeBuiltins", "compile_state_check_unsafe_builtins"},
	{"CheckDeprecatedBuiltins", "compile_state_check_deprecated_builtins"},
	{"BuildRuleIndices", "compile_stage_rebuild_indices"},
	{"BuildComprehensionIndices", "compile_stage_rebuild_comprehension_indices"},
}

func CompilerStages(rego string) []CompileResult {
	c := ast.NewCompiler().
		WithEnablePrintStatements(true)

	result := make([]CompileResult, 0, len(stages)+1)
	result = append(result, CompileResult{
		Stage: "ParseModule",
	})
	mod, err := ast.ParseModule("a.rego", rego)
	if err != nil {
		result[0].Error = err.Error()
		return result
	}
	result[0].Result = mod

	for i := range stages {
		stage := stages[i]
		c = c.WithStageAfter(stage.name,
			ast.CompilerStageDefinition{
				Name:       stage.name + "Record",
				MetricName: stage.metricName + "_record",
				Stage: func(c0 *ast.Compiler) *ast.Error {
					result = append(result, CompileResult{
						Stage:  stage.name,
						Result: getOne(c0.Modules),
					})
					return nil
				},
			})
	}
	c.Compile(map[string]*ast.Module{
		"a.rego": mod,
	})
	if len(c.Errors) > 0 {
		result[len(result)-1].Error = c.Errors.Error()
	}
	return result
}

func getOne(mods map[string]*ast.Module) *ast.Module {
	for _, m := range mods {
		return m.Copy()
	}
	panic("unreachable")
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bs, err := httputil.DumpRequest(r, true)
		if err != nil {
			panic(err)
		}
		log.Printf("Request %s", string(bs))

		templateName := r.URL.Query().Get("tmpl")
		if templateName == "" {
			templateName = "main"
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			code = exampleCode
		}
		cs := CompilerStages(code)
		st := state{
			Code:   code,
			Result: cs,
		}
		sel := r.URL.Query().Get("stage")
		if sel == "" {
			sel = cs[0].Stage
		}
		for i := range cs {
			switch {
			case cs[i].Stage != sel: // next
			case cs[i].Error != "":
				st.Selected = cs[i].Error
			case cs[i].Result != nil:
				st.Selected = cs[i].Result.String()
			}
		}
		if err := tpl.ExecuteTemplate(w, templateName, st); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	log.Println("starting: http:/127.0.0.1:9000")
	panic(http.ListenAndServe("127.0.0.1:9000", nil))
}