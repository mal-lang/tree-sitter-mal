/**
 * @file IT systems are growing in complexity and the threat from cyberattacks is increasing. Threat modeling is a process that can be used to analyze potential attacks to IT systems in order to facilitate secure design. Meta Attack Language (MAL) is a threat modeling language framework for the creation of domain specific languages (DSL). MAL is developed at KTH Royal Institute of Technology.
 * @author Andreas Hammarstrand <andreas.hammarstrand@gmail.com>
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

module.exports = grammar({
  name: "mal",

  extras: $ => [
    /[ \t\r\n]+/,
    $.comment,
  ],

  word: $ => $.identifier,

  conflicts: $ => [
    // FIXME: Conflict at end of association when there shouldn't be one
    [$.association]
  ],

  precedences: $ => [
    [ 'binary_exp', 'binary_mul', 'binary_plus', ]
  ],

  rules: {
    source_file: $ => repeat($.declaration),

    // http://stackoverflow.com/questions/13014947/regex-to-match-a-c-style-multiline-comment/36328890#36328890
    // Additionally, set 0 precidence so behavior can be overwritten when necessary.
    // For example: Detectors have //! accepted as part of backwards compatability.
    comment: _ => token(prec(0, choice(
      seq('//', /[^\r\n\u2028\u2029]*/),
      seq(
        '/*',
        /[^*]*\*+([^/*][^*]*\*+)*/,
        '/',
      ),
    ))),

    declaration: $ => choice(
      $.include_declaration,
      $.category_declaration,
      $.define_declaration,
      $.associations_declaration,
    ),

    include_declaration: $ => seq(
      'include',
      field('file', $.string)
    ),

    category_declaration: $ => seq(
      'category',
      field('id', $.identifier),
      field('meta', repeat($.meta)),
      '{',
      field('assets', repeat($.asset_declaration)),
      '}',
    ),

    // An asset for a category
    asset_declaration: $ => seq(
      optional(alias('abstract', 'abstract')),
      'asset',
      field('id', $.identifier),
      field('extends', optional(seq('extends', $.identifier))),
      field('meta', repeat($.meta)),
      '{',
      optional(field('body', $.asset_definition)),
      '}',
    ),

    asset_definition: $ => repeat1(choice($.attack_step, $.asset_variable)),

    // A varaible within an asset
    asset_variable: $ => seq(
      'let',
      field('id', $.identifier),
      '=',
      field('value', $.asset_expr),
    ),

    // Attack step for an asset
    attack_step: $ => seq(
      field('step_type', $.step_type),
      optional(field('causal_mode', $.step_causal_mode)),
      field('id', $.identifier),
      optional(field('tag', repeat(seq('@', $.identifier)))),
      optional(field('cias', seq(
        '{',
        $.cias,
        '}',
      ))),
      optional(field('ttc', $.ttc)),
      field('meta', repeat($.meta)),
      optional(field('detector', repeat($.detector))),
      optional(field('preconditions', $.preconditions)),
      optional(field('reaches', $.reaching)),
    ),

    step_type: $ => token(choice(
      '|',
      '&',
      '#',
      'E',
      '!E',
    )),

    step_causal_mode: $ => choice(
      'action',
      'effect',
    ),

    cias: $ => commaSep1($.cia),

    // Detector for attack steps
    detector: $ => seq(
      // Increase //! precidence to overrule comments
      choice('!', token(prec(1, '//!'))),
      optional(field('name', $.detector_name)),
      field('context', $.detector_context),
      optional(field('type', $.identifier)),
      optional(field('ttc', $.ttc)),
    ),

    detector_name: $ => sep1($.identifier, '.'),

    detector_context: $ => seq(
      '(',
      commaSep1($.detector_context_asset),
      ')',
    ),

    detector_context_asset: $ => seq(
      field('type', $.identifier),
      field('id', $.identifier),
    ),

    // Precondition for attack steps
    preconditions: $ => seq(
      '<-', 
      field('condition', commaSep1($.asset_expr))
    ),

    // Inheritence or lead to/from other identities for attack steps
    reaching: $ => seq(
        field('operator', choice('+>', '->')),
        field('reaches', commaSep1($.asset_expr))
    ),


    // Time-To-Compromise probabilty distributions
    ttc: $ => seq(
      '[',
      $._ttc_expr,
      ']',
    ),

    // No use in being known since there is only one place these can occur.
    // Might want to bring forward for the sake of querrying.
    _ttc_expr: $ => choice(
      $._ttc_parenthesized,
      $._ttc_primary,
      $.ttc_binop,
    ),

    _ttc_parenthesized: $ => seq('(', $._ttc_expr, ')'),

    _ttc_primary: $ => choice(
      $._number,
      $.identifier,
      $.ttc_distribution,
    ),

    ttc_distribution: $ => seq(
      field('id', $.identifier),
      '(',
      field('values', optional(commaSep1($._number))),
      ')',
    ),

    ttc_binop: $ => choice(
      ...[
        ['+', 'binary_plus'],
        ['-', 'binary_plus'],
        ['*', 'binary_mul'],
        ['/', 'binary_mul'],
        ['^', 'binary_exp', 'right'],
      ].map(([operator, precedence, associativity]) =>
        (associativity === 'right' ? prec.right : prec.left)(precedence, seq(
          field('left', $._ttc_expr),
          field('operator', operator),
          field('right', $._ttc_expr),
        )),
      )
    ),

    // Expression to define relations between assets
    asset_expr: $ => $._inline_asset_expr,

    // In order to ensure that asset_expr only occurs as a root node all of 
    // the grammar logic is placed inside this inline node
    _inline_asset_expr: $ => choice(
      // alias to ._ to inline
      seq('(', $._inline_asset_expr, ')', ),
      $._asset_expr_primary,
      $.asset_expr_binop,
      $.asset_expr_unop,
      $.asset_expr_type,
    ),


    _asset_expr_primary: $ => choice(
      $.identifier,
      $.asset_variable_substitution
    ),

    asset_variable_substitution: $ => seq(
      field('id', $.identifier),
      '(',
      ')',
    ),

    asset_expr_type: $ => prec.left('binary_exp', seq(
      field('expression', $._inline_asset_expr),
      '[',
      field('type_id', $.identifier),
      ']',
    )),

    asset_expr_binop: $ => choice(
      ...[
        ['\\/', 'binary_plus'],
        ['/\\', 'binary_plus'],
        ['-', 'binary_plus'],
        ['.', 'binary_mul'],
      ].map(([operator, precedence, associativity]) =>
        (associativity === 'right' ? prec.right : prec.left)(precedence, seq(
          field('left', $._inline_asset_expr),
          field('operator', operator),
          field('right', $._inline_asset_expr),
        )),
      )
    ),

    asset_expr_unop: $ => choice(
      ...[
        // For now only one unary operator so use binary precedences
        ['*', 'binary_exp'],
      ].map(([operator, precedence, associativity]) =>
        (associativity === 'right' ? prec.right : prec.left)(precedence, seq(
          field('expression', $._inline_asset_expr),
          field('operator', operator),
        )),
      )
    ),

    // Define values, i.e. global string constants
    define_declaration: $ => seq(
      '#',
      field('id', $.identifier),
      ':',
      field('value', $.string)
    ),

    // Define associations between categories, assets, etc. 
    // Quantitive relationships like in UML/relational database.
    associations_declaration: $ => seq(
      'associations',
      '{',
      repeat($.association),
      '}',
    ),

    association: $ => seq(
      field('left_id', $.identifier),
      '[', field('left_field_id', $.identifier), ']',
      field('left_mult', $.multiplicity),
      '<--',
      field('id', $.identifier),
      '-->',
      field('right_mult', $.multiplicity),
      '[', field('right_field_id', $.identifier), ']',
      field('right_id', $.identifier),
      field('meta', repeat($.meta)),
    ),

    // Multiplicity of an association, * for unbounded, range for bounded, and integer for exact.
    multiplicity: $ => choice(
      $._multiplicity_atom,
      $.multiplicity_range,
    ),

    _multiplicity_atom: $ => choice(
      $.integer,
      $.star,
    ),

    multiplicity_range: $ => seq(
      field('start', $._multiplicity_atom),
      '..',
      field('end', $._multiplicity_atom),
    ),

    // Meta information for category, asset, or otherwise.
    meta: $ => seq(
      field('id', $.identifier),
      'info',
      ':',
      field('info', alias($.string, $.meta_string)),
    ),

    // Primitives/Primaries/Atoms
    string: _ => token(seq('"', /(?:\\"|[^"])*/, '"')),
    _number: $ => choice($.integer, $.float),
    integer: _ => token(/[0-9]+/),
    float: _ => token(/(:?[0-9]+(:?[.][0-9]*)?|[.][0-9]+)/),
    identifier: _ => token(/[a-zA-Z0-9_]+/),

    star: _ => token('*'),
    cia: _ => token(/[CIA]/)
  },
});

/**
 * Creates a rule to match one or more of the rules separated by a given token.
 *
 * @param {Rule} rule
 * @param {Token} token
 *
 * @returns {SeqRule}
 */
function sep1(rule, token) {
  return seq(rule, repeat(seq(token, rule)));
}

/**
 * Creates a rule to match one or more of the rules separated by a comma
 *
 * @param {Rule} rule
 *
 * @returns {SeqRule}
 */
function commaSep1(rule) {
  return sep1(rule, ',');
}
