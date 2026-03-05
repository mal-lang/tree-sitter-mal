; Brackets
[
 "{"
 "}"
 "("
 ")"
 "["
 "]"
] @punctuation.bracket

; Operators
([
  "<--"
  "-->"
   "+"
   "-"
   "/"
   "^"
   (step_type)
   "="
   "!"
   "//!"
   "<-"
   "+>"
   "->"
   "#"
   "\\/"
   "/\\"
   "-"
   "."
   ".."
   "@"
  ] @operator)

(ttc_binop "*" @operator)
(asset_expr_unop "*" @operator)


; Keywords
"include" @keyword.import
[
  "category"
  "asset"
] @keyword.type
[
  "abstract"
  "extends"
  "associations"
] @keyword.modifier
"let" @keyword

; Delimiters
"," @punctuation.delimiter

(detector_name "." @punctuation.delimiter)

; Special
(cia) @constant.builtin
(meta) @comment
; Primitives
(string) @string

[
 (integer)
 (star)
] @number
(float) @number.float

; Semantic objects
(define_declaration id: (identifier) @constant)
(ttc_distribution id: (identifier) @function.builtin)
(ttc (identifier) @type)
(category_declaration id: (identifier) @module)
(association
  left_id: (identifier) @type
  left_field_id: (identifier) @property
  right_field_id: (identifier) @property
  right_id: (identifier) @type)
(asset_declaration
  [id: (identifier)
   extends: (identifier)] @type)
(detector_context_reference
  ctx_step: (asset_expr
    (identifier) @property)
  id: (identifier) @variable)
(asset_variable_substitution
  id: (identifier) @variable)
(asset_variable
  id: (identifier) @variable)

(asset_expr (identifier) @property)
(asset_expr [(identifier) @function
             (asset_expr_binop
               left: (_)*
               operator: "."
               right: (identifier) @function)] .)

; Miscellaneous
(comment) @comment
(attack_step (identifier) @tag
             (#not-match? @tag "hidden|debug|trace"))
(attack_step (identifier) @tag.builtin
             (#match? @tag.builtin "hidden|debug|trace"))

; tp_fp_rate highlighting
(tp_fp_rate
  "tpr" @property)

(tp_fp_rate
  "fpr" @property)

(tp_fp_rate
  ":" @punctuation.delimiter)

(tp_fp_rate
  "," @punctuation.delimiter)

(tp_fp_rate
  (float) @number.float)