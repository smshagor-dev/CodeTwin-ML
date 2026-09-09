; CodeTwin-owned TypeScript/TSX definition query.
; The upstream tree-sitter-typescript TAGS_QUERY intentionally focuses on
; signatures and type references, so production declarations need explicit
; CodeTwin coverage here.

(function_declaration
  name: (identifier) @name) @definition.function

(generator_function_declaration
  name: (identifier) @name) @definition.function

(function_signature
  name: (identifier) @name) @definition.function

(class_declaration
  name: (_) @name) @definition.class

(abstract_class_declaration
  name: (_) @name) @definition.class

(interface_declaration
  name: (_) @name) @definition.interface

(type_alias_declaration
  name: (_) @name) @definition.type

(method_definition
  name: (_) @name) @definition.method

(method_signature
  name: (_) @name) @definition.method

(abstract_method_signature
  name: (_) @name) @definition.method

(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: [(arrow_function) (function_expression)]) @definition.function)

(variable_declaration
  (variable_declarator
    name: (identifier) @name
    value: [(arrow_function) (function_expression)]) @definition.function)
