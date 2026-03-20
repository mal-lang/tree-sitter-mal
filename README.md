# tree-sitter-mal

MAL grammar for [tree-sitter](https://github.com/tree-sitter/tree-sitter). Used in the MAL-toolbox to parse MAL languages.

References
- [MAL Specification](https://github.com/mal-lang/mal-specification)
  - [MAL Languages Syntax](https://github.com/mal-lang/mal-specification/wiki/MAL-Syntax)
- [MAL Compiler Wiki](https://github.com/mal-lang/malcompiler/wiki/)
  - [MAL Language Specification](https://github.com/mal-lang/malcompiler/wiki/MAL-language-specification)
- [MAL Grammar Implementation](https://github.com/mal-lang/mal-toolbox/blob/main/maltoolbox/language/compiler/mal.g4)
- [MAL Vim Syntax Highlighting](https://github.com/nkakouros-original/mal.vim)

## Usage
[Install tree sitter CLI](https://github.com/tree-sitter/tree-sitter/blob/master/cli/README.md) to be able to use this grammar. Then, run `tree-sitter generate` to generate the parser from the grammar and `tree-sitter test` to test the parser, as well as the syntax highlighting and code navigation queries.

To see the parse tree the parser generates, use the command [`tree-sitter parse`](https://tree-sitter.github.io/tree-sitter/cli/parse.html).

To use the highlight through the command line, make sure you have a [config file initialized](https://tree-sitter.github.io/tree-sitter/cli/init-config.html). Then, you can use your own highlighting colors or copy the ones in the repository, specialized for MAL. Lastly, use `tree-sitter highlight` to generate an output, see the [docs](https://tree-sitter.github.io/tree-sitter/cli/highlight.html) for more information.

For more commands see [tree sitter CLI docs](https://tree-sitter.github.io/tree-sitter/cli/index.html) and the [tree-sitter-mal Wiki](Wiki).

### NeoVim Manual Installation
> [!NOTE]
> Tested for NeoVim v0.11.1.

#### Using [`nvim-treesitter`](https://github.com/nvim-treesitter/nvim-treesitter/blob/master/README.md#adding-parsers)

1. Install the grammar. Simply add the following Lua snippet to your configuration (`init.lua` or respective package config)
    ```lua
    local parser_config = require "nvim-treesitter.parsers".get_parser_configs()
    parser_config.mal = {
      install_info = {
        url = "https://github.com/Tobiky/tree-sitter-mal", -- local path or git repo
        files = {"src/parser.c"},
        branch = "main",
        generate_requires_npm = false,
        requires_generate_from_grammar = false,
      },
      filetype = "mal",
    }
    vim.filetype.add({
        extension = {
            mal = "mal",
        },
    })
    ```
2. Install the queries. Find the query installation folder (it will be in your runtime path, `:h rtp`). You can find various locations by using e.g. `find ~ -type d -and -iname "queries"` (**NOTE:** This example only looks at files installed in your home directory). An example of the path can be `$HOME/.local/share/nvim/lazy/nvim-treesitter/` if you are using the Lazy PM. Install the files from `queries` into a directory named after the language (`cp -r queries $NVIM_TREESITTER_QUERIES/mal/`).
3. Verify that everything is installed by running a healthcheck `:checkhealth nvim-treesitter`, the table will list if the grammar and highlighting has been found.
4. Configure Nvim to start tree-sitter. Here is an example using auto-commands:
    ```lua
    vim.api.nvim_create_autocmd( 'FileType', { pattern = 'mal',
        callback = function(args)
            vim.treesitter.start(args.buf, 'mal')
        end
    })
    ```
