local Ast = {}
function Ast.new() return { data = { statements = {} } } end
function Ast.addStatement(ast, stmt) table.insert(ast.data.statements, stmt) end
function Ast.Variable(name) return { kind = "variable", data = { name = name } } end
function Ast.String(value) return { kind = "string", data = { value = value } } end
function Ast.Number(value) return { kind = "number", data = { value = value } } end
function Ast.Boolean(value) return { kind = "boolean", data = { value = value } } end
function Ast.Nil() return { kind = "nil" } end
function Ast.Assign(vars, values, isGlobal) return { kind = "assign", data = { vars = vars, values = values, global = isGlobal } } end
function Ast.FunctionCall(func, args) return { kind = "call", data = { func = func, arguments = args } } end
function Ast.Index(base, key) return { kind = "index", data = { base = base, key = key } } end
function Ast.Namecall(base, method, args) return { kind = "namecall", data = { base = base, method = method, arguments = args } } end
function Ast.BinaryOp(left, op, right) return { kind = "binary", data = { left = left, operator = op, right = right } } end
function Ast.UnaryOp(expr, op) return { kind = "unary", data = { expression = expr, operator = op } } end
function Ast.Table(fields) return { kind = "table", data = { fields = fields } } end
function Ast.Function(params, body) return { kind = "function", data = { parameters = params, body = body } } end
function Ast.Block(statements) return { kind = "block", data = { statements = statements or {} } } end
function Ast.IfStat(condition, body, elseBody) return { kind = "if", data = { condition = condition, body = body, elseBody = elseBody } } end
function Ast.WhileLoop(condition, body) return { kind = "while", data = { condition = condition, body = body } } end
function Ast.ForPrep(var, iterVar, iterator, id) return { kind = "forprep", data = { var = var, iterVar = iterVar, iterator = iterator, id = id } } end
function Ast.ForNum(var, start, end_, step, body) return { kind = "fornum", data = { var = var, start = start, ["end"] = end_, step = step, body = body } } end
function Ast.End(id) return { kind = "end", data = { id = id } } end
function Ast.Comment(...) return { kind = "comment", data = { text = ... } } end
function Ast.PermaComment(...) return { kind = "permacomment", data = { text = ... } } end
function Ast.NonOptionalComment(...) return { kind = "nonoptionalcomment", data = { text = ... } } end
function Ast.RawText(text) return text end
function Ast.Return(values) return { kind = "return", data = { arguments = values } } end
function Ast.Group(expr) return expr end
function Ast.IsAst(node) return type(node) == "table" and node.kind ~= nil end

local AstLib = { Ast = Ast }
function AstLib.Minify(ast, beautify) return ast end
function AstLib.Stringify(ast) return "return {}" end
function AstLib.SetGlobal(key, value) end
function AstLib.ExprToCode(expr, indent, raw) return "" end

return AstLib
