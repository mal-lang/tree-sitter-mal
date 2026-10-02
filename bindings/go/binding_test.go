package tree_sitter_mal_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_mal "github.com/mal-lang/tree-sitter-mal/bindings/go"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_mal.Language())
	if language == nil {
		t.Errorf("Error loading Mal grammar")
	}
}
