// Copyright 2022 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

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
import input.roles

# METADATA
# entrypoint: true
allow := "admin" in roles if {
	print(roles)
	some x in roles
	x == "janitor"
}
`

var tpl = template.Must(template.New("main").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8"/>
		<link rel="stylesheet" href="https://the.missing.style/v1.0.3/missing.min.css">
		<script src="https://unpkg.com/htmx.org@1.8.4" integrity="sha384-wg5Y/JwF7VxGk4zLsJEcAojRtlVp1FKKdGy1qN+OMtdq72WRvX/EdRdqg/LOhYeV" crossorigin="anonymous"></script>
	<body>
		<header>
			<h1>OPA Explorer<v-h>:</v-h><sub-title>Inspect compiler stages</sub-title></h1>
			<nav>
				<p class="tool-bar">
					<object data="https://img.shields.io/badge/OPA-0.46.1-green?link=https://openpolicyagent.org/docs/v0.46.1&style=flat-square&labelColor=f2f4f6&logo=data:image/png;base64,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"></object>
					<a href="https://github.com/srenatus/opa-explorer">GitHub</a>
				</p>
			</nav>
		</header>
		<main class="crowded">
			<form>
				<div class="f-row">
					<textarea name="code"
					  style="height: 300px"
					  hx-post="/?tmpl=output"
					  hx-target="#output"
					  hx-trigger="keyup changed delay:200ms"
					  class="flex-grow:1 monospace"
					>{{ .Code }}</textarea>
				</div>
			</form>
			<section id="output">
				{{ block "output" . }}
				{{ range .Result }}
				<details {{ if .Show }}open{{ end }}>
					<summary class={{ .Class }}>{{ .Stage }}</summary>
					<pre><code>{{ .Output }}</code></pre>
				</details>
				{{ end }}
				{{ end }}
			</section>
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
	Code   string
	Result []stringResult
}

type stringResult struct {
	Show   bool
	Class  string
	Stage  string
	Output string
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

func CompilerStages(rego string, strict, anno, print bool) []CompileResult {
	c := ast.NewCompiler().
		WithStrict(strict).
		WithEnablePrintStatements(print)

	result := make([]CompileResult, 0, len(stages)+1)
	result = append(result, CompileResult{
		Stage: "ParseModule",
	})
	mod, err := ast.ParseModuleWithOpts("a.rego", rego, ast.ParserOptions{ProcessAnnotation: anno})
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
		if err := r.ParseForm(); err != nil {
			panic(err)
		}
		code := r.Form.Get("code")
		if code == "" {
			code = exampleCode
		}
		strict := r.Form.Get("strict") == "on"
		anno := r.Form.Get("annotations") == "on"
		print := r.Form.Get("print") == "on"
		cs := CompilerStages(code, strict, print, anno)
		st := state{
			Code: code,
		}
		st.Result = make([]stringResult, len(cs))
		for i := range cs {
			st.Result[i].Stage = cs[i].Stage
			if cs[i].Error != "" {
				st.Result[i].Output = cs[i].Error
				st.Result[i].Class = "bad"
			} else {
				st.Result[i].Output = cs[i].Result.String()
			}
			st.Result[i].Show = i == 0 || st.Result[i-1].Output != st.Result[i].Output
			if st.Result[i].Class == "" {
				if st.Result[i].Show {
					st.Result[i].Class = "ok"
				} else {
					st.Result[i].Class = "plain"
				}
			}
		}
		if err := tpl.ExecuteTemplate(w, templateName, st); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	log.Println("starting: http:/127.0.0.1:9000")
	panic(http.ListenAndServe("127.0.0.1:9000", nil))
}
