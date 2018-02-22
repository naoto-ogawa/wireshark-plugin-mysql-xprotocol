--[[
Module      : xprotocol.lua
Description : Wireshark plugin for MySQL XProtocol 
Copyright   : (c) Naoto Ogawa, 2018
License     : GPL
Maintainer  : becausethespiderspiedher+wiresharkxprotocol(at)email.com
Stability   : experimental

Reference XProtocol 
 https://dev.mysql.com/doc/internals/en/x-protocol.html

--]]

local xproto_info = {
  version     = "0.0.1",
  author      = "naoto ogawa",
  description = "a dissector plugin for MySQL XProtocol",
  repository  = "https://github.com/naoto-ogawa/wireshark-plugin-mysql-xprotocol"
}
set_plugin_info(xproto_info)

local xproto = Proto ("XProtocol", "X Protocol Dissector");

function xproto.init () 
end

-- Preferences
local p = xproto.prefs
p.server_port = Pref.uint ("server port", 8000, "server port number") -- TODO 33060 should be default
p.show_detail = Pref.bool ("show detail (protocol buffer wire_type and tag_no, etc.)", false, "show detail")

-- Fields
local f = xproto.fields

f.message   = ProtoField.bytes  ("XProtocol.message"   , "Message"    )
f.size      = ProtoField.bytes  ("XProtocol.size"      , "Size"       )
f.tipe      = ProtoField.bytes  ("XProtocol.type"      , "Type"       )
f.pbitem    = ProtoField.bytes  ("XProtocol.pbitem"    , "proto item" ) -- default , fail safe

-- protocol buffer data type
local terminal_type = {
   "double"
  ,"float"
  ,"int32"
  ,"int64"
  ,"uint32"
  ,"uint64"
  ,"sint32"
  ,"sint64"
  ,"fixed32"
  ,"fixed64"
  ,"sfixed32"
  ,"sfixed64"
  ,"bool"
  ,"string"
  ,"bytes"
}

-- mysql_connection.proto
Capability = {
  [1] = {attr = "required", type = "string" , name = "name"  , tag = 1}
 ,[2] = {attr = "required", type = "Any"    , name = "value" , tag = 2}
}
Capabilities = {
  [1] = {attr = "repeated", type = "Capability" , name="capabilities", tag  = 1}
}
CapabilitiesGet = {
}
CapabilitiesSet = {
  [1] = {attr = "repeated", type = "Capabilities" , name="capabilities", tag  = 1}
}
ConClose = {
}
-- mysql_datatypes.proto
String = {
   [1] = {attr = "required" , type = "bytes"  , name="value"     , tag = 1}
  ,[2] = {attr = "optional" , type = "uint64" , name="collation" , tag = 2}
}
Octets = {
   [1] = {attr = "required" , type = "bytes"  , name = "value"        , tag = 1}
  ,[2] = {attr = "optional" , type = "uint32" , name = "content_type" , tag = 2}
}
Scalar = {
  Type = {
     [1] = "V_SINT"
    ,[2] = "V_UINT"
    ,[3] = "V_NULL"
    ,[4] = "V_OCTETS"
    ,[5] = "V_DOUBLE"
    ,[6] = "V_FLOAT"
    ,[7] = "V_BOOL"
    ,[8] = "V_STRING"
  }
  ,[1] = {attr = "required" , type = "Type"   , name = "type"           , tag = 1}
  ,[2] = {attr = "optional" , type = "sint64" , name = "v_signed_int"   , tag = 2}
  ,[3] = {attr = "optional" , type = "uint64" , name = "v_unsigned_int" , tag = 3}
  ,[5] = {attr = "optional" , type = "Octets" , name = "v_octets"       , tag = 5}
  ,[6] = {attr = "optional" , type = "double" , name = "v_double"       , tag = 6}
  ,[7] = {attr = "optional" , type = "float"  , name = "v_float"        , tag = 7}
  ,[8] = {attr = "optional" , type = "bool"   , name = "v_bool"         , tag = 8}
  ,[9] = {attr = "optional" , type = "String" , name = "v_string"       , tag = 9}
  ,enum_fun = function(v) return Scalar.Type[v] end
}
Scalar[1].converter = Scalar.enum_fun

ObjectFieldAny = {
   [1] = {attr = "required" , type = "string", name = "key"   , tag = 1}
  ,[2] = {attr = "required" , type = "Any"   , name = "value" , tag = 2}
}

ObjectAny = {
  [1] = {attr = "repeated" , type = "ObjectFieldAny", name = "fld", tag = 1}
}

ArrayAny = {
  [1] = {attr = "repeated" , type = "Any", name = "value", tag = 1}
}

Any = {
  Type = {
     [1] = "SCALAR"
    ,[2] = "OBJECT"
    ,[3] = "ARRAY"
  }
  , [1] = {attr = "required" , type = "Type"      , name = "type"   , tag = 1}
  , [2] = {attr = "optional" , type = "Scalar"    , name = "scalar" , tag = 2}
  , [3] = {attr = "optional" , type = "ObjectAny" , name = "obj"    , tag = 3}
  , [4] = {attr = "optional" , type = "ArrayAny"  , name = "array"  , tag = 4}
  , enum_fun = function(v) return Any.Type[v] end
}
Any[1].converter = Any.enum_fun

-- mysqlx_crud.proto
Column = {
   [1] = {attr = "optional", type = "string",           name="name",          tag = 1}
 , [2] = {attr = "optional", type = "string",           name="alias",         tag = 2}
 , [3] = {attr = "repeated", type = "DocumentPathItem", name="document_path", tag = 3}
}
Projection = {
   [1] = {attr = "required", type = "Expr",   name="source", tag = 1}
 , [2] = {attr = "optional", type = "string", name="alias",  tag = 2}
}
DataModel = {
  [1] = "DOCUMENT"
 ,[2] = "TABLE"
 ,enum_fun = function(v) return DataModel[v] end
}
Collection = {
  [1] = {attr = "required" , type = "string" , name="name"   , tag = 1}
 ,[2] = {attr = "optional" , type = "string" , name="schema" , tag = 2}
}
Limit = {
  [1] = {attr = "required" , type = "uint64" , name="row_count" , tag = 1}
 ,[2] = {attr = "optional" , type = "uint64" , name="offset"    , tag = 2}
}
Order = {
  Direction = {
    [1] = "ASC"
   ,[2] = "DESC"
  }
 , [1] = {attr = "required", type = "Expr",      name="expr",      tag = 1}
 , [2] = {attr = "optional", type = "Direction", name="direction", tag = 2}
 , enum_fun = function(v) return Order.Direction[v] end
}
Order[2].converter = Order.enum_fun

UpdateOperation = {
  UpdateType = {
    [1] = "SET"
   ,[2] = "ITEM_REMOVE"
   ,[3] = "ITEM_SET"
   ,[4] = "ITEM_REPLACE"
   ,[5] = "ITEM_MERGE"
   ,[6] = "ARRAY_INSERT"
   ,[7] = "ARRAY_APPEND"
  }
 , [1] = {attr = "required", type = "ColumnIdentifier", name="source",    tag = 1}
 , [2] = {attr = "required", type = "UpdateType",       name="operation", tag = 2}
 , [3] = {attr = "optional", type = "Expr",             name="value",     tag = 3}
 , enum_fun = function(v) return UpdateOperation.UpdateType[v] end
}
UpdateOperation[2].converter = UpdateOperation.enum_fun

Find = {
   [2]  = {attr = "required", type = "Collection", name="collection",        tag = 2}
 , [3]  = {attr = "optional", type = "DataModel",  name="data_model",        tag = 3, converter = DataModel.enum_fun}
 , [4]  = {attr = "repeated", type = "Projection", name="projection",        tag = 4}
 , [5]  = {attr = "optional", type = "Expr",       name="criteria",          tag = 5}
 , [11] = {attr = "repeated", type = "Scalar",     name="args",              tag = 11}
 , [6]  = {attr = "optional", type = "Limit",      name="limit",             tag = 6}
 , [7]  = {attr = "repeated", type = "Order",      name="order",             tag = 7}
 , [8]  = {attr = "repeated", type = "Expr",       name="grouping",          tag = 8}
 , [9]  = {attr = "optional", type = "Expr",       name="grouping_criteria", tag = 9}
}
TypedRow = {
  [1] = {attr = "repeated" , type = "Expr" , name="field" , tag = 1}
}
Insert = {
   [1] = {attr = "required", type = "Collection", name="collection", tag = 1}
 , [2] = {attr = "optional", type = "DataModel",  name="data_model", tag = 2, converter = DataModel.enum_fun}
 , [3] = {attr = "repeated", type = "Column",     name="projection", tag = 3}
 , [4] = {attr = "repeated", type = "TypedRow",   name="row",        tag = 4}
 , [5] = {attr = "repeated", type = "Scalar",     name="args",       tag = 5}
}
Update = {
   [2] = {attr = "required", type = "Collection",      name="collection", tag = 2}
 , [3] = {attr = "optional", type = "DataModel",       name="data_model", tag = 3, converter = DataModel.enum_fun}
 , [4] = {attr = "optional", type = "Expr",            name="criteria",   tag = 4}
 , [8] = {attr = "repeated", type = "Scalar",          name="args",       tag = 8}
 , [5] = {attr = "optional", type = "Limit",           name="limit",      tag = 5}
 , [6] = {attr = "repeated", type = "Order",           name="order",      tag = 6}
 , [7] = {attr = "repeated", type = "UpdateOperation", name="operation",  tag = 7}
}
Delete = {
   [1] = {attr = "required", type = "Collection", name="collection", tag = 1}
 , [2] = {attr = "optional", type = "DataModel",  name="data_model", tag = 2, converter = DataModel.enum_fun}
 , [3] = {attr = "optional", type = "Expr",       name="criteria",   tag = 3}
 , [6] = {attr = "repeated", type = "Scalar",     name="args",       tag = 6}
 , [4] = {attr = "optional", type = "Limit",      name="limit",      tag = 4}
 , [5] = {attr = "repeated", type = "Order",      name="order",      tag = 5}
}
ViewAlgorithm = {
  [1] = "UNDEFINED"
 ,[2] = "MERGE"
 ,[3] = "TEMPTABLE"
 ,enum_fun = function(v) return ViewAlgorithm[v] end
}
ViewSqlSecurity = {
  [1] = "INVOKER"
 ,[2] = "DEFINER"
 ,enum_fun = function(v) return ViewSqlSecurity[v] end
}
ViewCheckOption = {
  [1] = "LOCAL"
 ,[2] = "CASCADED"
 ,enum_fun = function(v) return ViewCheckOption[v] end
}
CreateView = {
   [1] = {attr = "required", type = "Collection",      name="collection",       tag = 1}
 , [2] = {attr = "optional", type = "string",          name="definer",          tag = 2}
 , [3] = {attr = "optional", type = "ViewAlgorithm",   name="algorithm",        tag = 3, converter = ViewAlgorithm.enum_fun}
 , [4] = {attr = "optional", type = "ViewSqlSecurity", name="security",         tag = 4, converter = ViewSqlSecurity.enum_fun}
 , [5] = {attr = "optional", type = "ViewCheckOption", name="check",            tag = 5, converter = ViewCheckOption.enum_fun}
 , [6] = {attr = "repeated", type = "string",          name="column",           tag = 6}
 , [7] = {attr = "required", type = "Find",            name="stmt",             tag = 7}
 , [8] = {attr = "optional", type = "bool",            name="replace_existing", tag = 8}
}
ModifyView = {
   [1] = {attr = "required", type = "Collection",      name="collection", tag = 1}
 , [2] = {attr = "optional", type = "string",          name="definer",    tag = 2}
 , [3] = {attr = "optional", type = "ViewAlgorithm",   name="algorithm",  tag = 3, converter = ViewAlgorithm.enum_fun}
 , [4] = {attr = "optional", type = "ViewSqlSecurity", name="security",   tag = 4, converter = ViewSqlSecurity.enum_fun}
 , [5] = {attr = "optional", type = "ViewCheckOption", name="check",      tag = 5, converter = ViewCheckOption.enum_fun}
 , [6] = {attr = "repeated", type = "string",          name="column",     tag = 6}
 , [7] = {attr = "optional", type = "Find",            name="stmt",       tag = 7}
}
DropView = {
  [1] = {attr = "required" , type = "Collection" , name="collection" , tag = 1}
 ,[2] = {attr = "optional" , type = "bool"       , name="if_exists"  , tag = 2}
}
-- mysqlx_expect.proto
Condition = {
  ConditionKey = {
     [1] = "no_error"
    ,[2] = "schema_version"
    ,[3] = "gtid_executed_contains"
    ,[4] = "gtid_wait_less_than_ms" 
  }
  , ConditionOperation = {
    [0] = "EXPECT_OP_SET"
   ,[1] = "EXPECT_OP_UNSET"
  }
  , [1] = {attr = "required", type = "uint32",             name="condition_key",   tag = 1}
  , [2] = {attr = "optional", type = "bytes",              name="condition_value", tag = 2}
  , [3] = {attr = "optional", type = "ConditionOperation", name="op",              tag = 3}
  ,enum_fun = function(v) return Condition.ConditionOperation[v] end
  ,key_fun  = function(v) return Condition.ConditionKey[v] end
}
Condition[1].converter = Condition.key_fun 
Condition[3].converter = Condition.enum_fun 
ExpectOpen = {
  CtxOperation = {
    [0] = "EXPECT_CTX_COPY_PREV"
   ,[1] = "EXPECT_CTX_EMPTY"
  }
 ,[1] = {attr = "optional" , type = "CtxOperation" , name="op"   , tag = 1}
 ,[2] = {attr = "repeated" , type = "Condition"    , name="cond" , tag = 2}
 ,enum_fun = function(v) return ExpectOpen.CtxOperation[v] end
}
ExpectOpen[1].converter = ExpectOpen.enum_fun
ExpectClose = {
}
-- mysqlx_expr.proto
Expr = {
  Type = {
    [1] = "IDENT"
   ,[2] = "LITERAL"
   ,[3] = "VARIABLE"
   ,[4] = "FUNC_CALL"
   ,[5] = "OPERATOR"
   ,[6] = "PLACEHOLDER"
   ,[7] = "OBJECT"
   ,[8] = "ARRAY"
  }
 ,[1] = {attr = "required" , type = "Type"             , name="type"          , tag = 1}
 ,[2] = {attr = "optional" , type = "ColumnIdentifier" , name="identifier"    , tag = 2}
 ,[3] = {attr = "optional" , type = "string"           , name="variable"      , tag = 3}
 ,[4] = {attr = "optional" , type = "Scalar"           , name="literal"       , tag = 4}
 ,[5] = {attr = "optional" , type = "FunctionCall"     , name="function_call" , tag = 5}
 ,[6] = {attr = "optional" , type = "Operator"         , name="operator"      , tag = 6}
 ,[7] = {attr = "optional" , type = "uint32"           , name="position"      , tag = 7}
 ,[8] = {attr = "optional" , type = "Object"           , name="object"        , tag = 8}
 ,[9] = {attr = "optional" , type = "Array"            , name="array"         , tag = 9}
 ,enum_fun = function(v) return Expr.Type[v] end
}
Expr[1].converter = Expr.enum_fun
Identifier = {
  [1] = {attr = "required" , type = "string" , name="name"        , tag = 1}
 ,[2] = {attr = "optional" , type = "string" , name="schema_name" , tag = 2}
}
DocumentPathItem = {
  Type = {
    [1] = "MEMBER"
   ,[2] = "MEMBER_ASTERISK"
   ,[3] = "ARRAY_INDEX"
   ,[4] = "ARRAY_INDEX_ASTERISK"
   ,[5] = "DOUBLE_ASTERISK"
  }
 ,[1] = {attr = "required" , type = "Type"   , name="type" , tag = 1}
 ,[2] = {attr = "optional" , type = "string" , name="value" , tag = 2}
 ,[3] = {attr = "optional" , type = "uint32" , name="index" , tag = 3}
 ,enum_fun = function(v) return DocumentPathItem.Type[v] end
}
DocumentPathItem[1].converter = DocumentPathItem.enum_fun 
ColumnIdentifier = {
  [1] = {attr = "repeated" , type = "DocumentPathItem" , name="document_path" , tag = 1}
 ,[2] = {attr = "optional" , type = "string"           , name="name"          , tag = 2}
 ,[3] = {attr = "optional" , type = "string"           , name="table_name"    , tag = 3}
 ,[4] = {attr = "optional" , type = "string"           , name="schema_name"   , tag = 4}
}
FunctionCall = {
  [1] = {attr = "required" , type = "Identifier" , name="name"  , tag = 1}
 ,[2] = {attr = "repeated" , type = "Expr"       , name="param" , tag = 2}
}
Operator = {
   [1] = {attr = "required", type = "string", name="name",  tag = 1}
 , [2] = {attr = "repeated", type = "Expr",   name="param", tag = 2}
}
ObjectField = {
   [1] = {attr = "required", type = "string", name="key",   tag = 1}
 , [2] = {attr = "required", type = "Expr",   name="value", tag = 2}
}
Object = {
  [1] = {attr = "repeated" , type = "ObjectField" , name="fld" , tag = 1}
}
Array = {
  [1] = {attr = "repeated" , type = "Expr" , name="value" , tag = 1}
}
-- mysqlx_notice.proto
FrameType = {
  [1] = {type = "Warning"                 , name="notice"  }
 ,[2] = {type = "SessionVariableChanged"  , name="notice"  }
 ,[3] = {type = "SessionStateChanged"     , name="notice"  }
} 
Frame = {
  Scope = {
    [1] = "GLOBAL"
   ,[2] = "LOCAL"
  }
 ,[1] = {attr = "required" , type = "uint32" , name="type"    , tag = 1}
 ,[2] = {attr = "optional" , type = "Scope"  , name="scope"   , tag = 2}
 ,[3] = {attr = "optional" , type = "bytes"  , name="payload" , tag = 3}
 ,enum_fun = function(v) return Frame.Scope[v] end
 ,type_fun = function(v) 
    local t = FrameType[v].type 
    Frame[3].type = t
    Frame[3].protofield_back = FrameType[v].protofield
    Frame[3].protofield = FrameType[v].protofield
    return t 
  end
 ,to_bytes = function() 
    Frame[3].type="bytes"
    Frame[3].protofield = Frame[3].protofield_back
    Frame[3].protofield_back = nil
  end
}
Frame[2].converter = Frame.enum_fun
Frame[1].type_fun  = Frame.type_fun
Frame[3].clear     = Frame.to_bytes
Warning = {
  Level = {
    [1] = "NOTE"
   ,[2] = "WARNING"
   ,[3] = "ERROR"
  }
 ,[1] = {attr = "optional" , type = "Level"  , name="level" , tag = 1}
 ,[2] = {attr = "required" , type = "uint32" , name="code"  , tag = 2}
 ,[3] = {attr = "required" , type = "string" , name="msg"   , tag = 3}
 ,enum_fun = function(v) return Warning.Level[v] end
}
Warning[1].converter = Warning.enum_fun
SessionVariableChanged = {
  [1] = {attr = "required" , type = "string" , name="param" , tag = 1}
 ,[2] = {attr = "optional" , type = "Scalar" , name="value" , tag = 2}
}
SessionStateChanged = {
  Parameter = {
    [1]  = "CURRENT_SCHEMA"
   ,[2]  = "ACCOUNT_EXPIRED"
   ,[3]  = "GENERATED_INSERT_ID"
   ,[4]  = "ROWS_AFFECTED"
   ,[5]  = "ROWS_FOUND"
   ,[6]  = "ROWS_MATCHED"
   ,[7]  = "TRX_COMMITTED"
   ,[9]  = "TRX_ROLLEDBACK"
   ,[10] = "PRODUCED_MESSAGE"
   ,[11] = "CLIENT_ID_ASSIGNED"
  }
 ,[1] = {attr = "required" , type = "Parameter" , name="param" , tag = 1}
 ,[2] = {attr = "optional" , type = "Scalar"    , name="value" , tag = 2}
 ,enum_fun = function(v) return SessionStateChanged.Parameter[v] end
}
SessionStateChanged[1].converter = SessionStateChanged.enum_fun
-- mysqlx_resultset.proto
FetchDoneMoreOutParams = {
}
FetchDoneMoreResultsets = {
}
FetchDone = {
}
ColumnMetaData = {
  FieldType = {
    [1]  = "SINT"
   ,[2]  = "UINT"
   ,[5]  = "DOUBLE"
   ,[6]  = "FLOAT"
   ,[7]  = "BYTES"
   ,[10] = "TIME"
   ,[12] = "DATETIME"
   ,[15] = "SET"
   ,[16] = "ENUM"
   ,[17] = "BIT"
   ,[18] = "DECIMAL"
  }
 ,flagsType = {
    [16]  = "NOT_NULL"       -- 0x0010 NOT_NULL
   ,[32]  = "PRIMARY_KEY "   -- 0x0020 PRIMARY_KEY
   ,[64]  = "UNIQUE_KEY"     -- 0x0040 UNIQUE_KEY
   ,[128] = "MULTIPLE_KEY"   -- 0x0080 MULTIPLE_KEY
   ,[256] = "AUTO_INCREMENT" -- 0x0100 AUTO_INCREMENT
  }
 ,contentType = {
    [1]  = "GEOMETRY"
   ,[2]  = "JSON"
   ,[3]  = "XML"
  }
 ,[1]  = {attr = "required" , type = "FieldType" , name="type"              , tag = 1}
 ,[2]  = {attr = "optional" , type = "bytes"     , name="name"              , tag = 2}
 ,[3]  = {attr = "optional" , type = "bytes"     , name="original_name"     , tag = 3}
 ,[4]  = {attr = "optional" , type = "bytes"     , name="table"             , tag = 4}
 ,[5]  = {attr = "optional" , type = "bytes"     , name="original_table"    , tag = 5}
 ,[6]  = {attr = "optional" , type = "bytes"     , name="schema"            , tag = 6}
 ,[7]  = {attr = "optional" , type = "bytes"     , name="catalog"           , tag = 7}
 ,[8]  = {attr = "optional" , type = "uint64"    , name="collation"         , tag = 8}
 ,[9]  = {attr = "optional" , type = "uint32"    , name="fractional_digits" , tag = 9}
 ,[10] = {attr = "optional" , type = "uint32"    , name="length"            , tag = 10}
 ,[11] = {attr = "optional" , type = "uint32"    , name="flags"             , tag = 11}
 ,[12] = {attr = "optional" , type = "uint32"    , name="content_type"      , tag = 12}
 ,enum_fun    = function(v) return ColumnMetaData.FieldType[v] end
 ,flags_fun   = function(x)
                   local ret=""
                   for k, v in pairs(ColumnMetaData.flagsType) do
                     if bit32.band(x,k)==k then ret = ret .. " " .. v end
                   end
                   return trim(ret)
                end
 ,content_fun = function(v) return ColumnMetaData.contentType[v] end
}
ColumnMetaData[1 ].converter = ColumnMetaData.enum_fun
ColumnMetaData[11].converter = ColumnMetaData.flags_fun
ColumnMetaData[12].converter = ColumnMetaData.content_fun
Row = {
  [1] = {attr = "repeated" , type = "bytes" , name="field" , tag = 1}
}
-- mysqlx_session.proto
AuthenticateStart = {
  [1] = {attr = "required" , type = "string" , name="mech_name"        , tag = 1}
 ,[2] = {attr = "optional" , type = "bytes"  , name="auth_data"        , tag = 2}
 ,[3] = {attr = "optional" , type = "bytes"  , name="initial_response" , tag = 3}
}
AuthenticateContinue = {
  [1] = {attr = "required" , type = "bytes" , name="auth_data" , tag = 1}
}
AuthenticateOk = {
  [1] = {attr = "optional" , type = "bytes" , name="auth_data" , tag = 1}
}
SessReset = {
}
SessClose = {
}
-- mysqlx_sql.proto
StmtExecute = {
  [1] = {attr = "required" , type = "bytes"  , name="stmt"             , tag = 1}
 ,[2] = {attr = "repeated" , type = "Any"    , name="args"             , tag = 2}
 ,[3] = {attr = "optional" , type = "string" , name="namespace"        , tag = 3}
 ,[4] = {attr = "optional" , type = "bool"   , name="compact_metadata" , tag = 4}
}
StmtExecuteOk = {
}
-- mysqlx.proto
clientmessagetype = {
    [1]  = {name = "CON_CAPABILITIES_GET",       type = "CapabilitiesGet",      }
  , [2]  = {name = "CON_CAPABILITIES_SET",       type = "CapabilitiesSet",      }
  , [3]  = {name = "CON_CLOSE",                  type = "ConClose",             }
  , [4]  = {name = "SESS_AUTHENTICATE_START",    type = "AuthenticateStart",    }
  , [5]  = {name = "SESS_AUTHENTICATE_CONTINUE", type = "AuthenticateContinue", }
  , [6]  = {name = "SESS_RESET",                 type = "SessReset",            }
  , [7]  = {name = "SESS_CLOSE",                 type = "SessClose",            }
  , [12] = {name = "SQL_STMT_EXECUTE",           type = "StmtExecute",          }
  , [17] = {name = "CRUD_FIND",                  type = "Find",                 }
  , [18] = {name = "CRUD_INSERT",                type = "Insert",               }
  , [19] = {name = "CRUD_UPDATE",                type = "Update",               }
  , [20] = {name = "CRUD_DELETE",                type = "Delete",               }
  , [24] = {name = "EXPECT_OPEN",                type = "ExpectOpen",           }
  , [25] = {name = "EXPECT_CLOSE",               type = "ExpectClose",          }
  , [30] = {name = "CRUD_CREATE_VIEW",           type = "CreateView",           }
  , [31] = {name = "CRUD_MODIFY_VIEW",           type = "ModifyView",           }
  , [32] = {name = "CRUD_DROP_VIEW",             type = "DropView",             }
}
--
servermessagetype = {
    [0]  = {name = "OK",                                   type = "Ok",                       }
  , [1]  = {name = "ERROR",                                type = "Error",                    }
  , [2]  = {name = "CONN_CAPABILITIES",                    type = "Capabilities",             }
  , [3]  = {name = "SESS_AUTHENTICATE_CONTINUE",           type = "AuthenticateContinue",     }
  , [4]  = {name = "SESS_AUTHENTICATE_OK",                 type = "AuthenticateOk",           }
  , [11] = {name = "NOTICE",                               type = "Frame",                    }
  , [12] = {name = "RESULTSET_COLUMN_META_DATA",           type = "ColumnMetaData",           }
  , [13] = {name = "RESULTSET_ROW",                        type = "Row",                      }
  , [14] = {name = "RESULTSET_FETCH_DONE",                 type = "FetchDone",                }
  , [15] = {name = "RESULTSET_FETCH_SUSPENDED",            type = "nil",                      } -- TODO, I haven't understand yet.
  , [16] = {name = "RESULTSET_FETCH_DONE_MORE_RESULTSETS", type = "FetchDoneMoreResultsets",  }
  , [17] = {name = "SQL_STMT_EXECUTE_OK",                  type = "StmtExecuteOk",            }
  , [18] = {name = "RESULTSET_FETCH_DONE_MORE_OUT_PARAMS", type = "FetchDoneMoreOutParams",   }
} 
Ok = {
  [1] = {attr = "optional" , type = "string", name ="msg" , tag  = 1}
}
Error = {
  Severity = {
    [0] = "ERROR"
   ,[1] = "FATAL"
  }
  ,[1] = {attr = "optional" , type = "Severity" , name="severity"  , tag = 1}
  ,[2] = {attr = "required" , type = "uint32"   , name="code"      , tag = 2}
  ,[3] = {attr = "required" , type = "string"   , name="msg"       , tag = 3}
  ,[4] = {attr = "required" , type = "string"   , name="sql_state" , tag = 4}
  ,enum_fun = function(v) return Error.Severity[v] end
}
Error[1].converter = Error.enum_fun

-- message_table
message_table = {
   Capability              = Capability
 , Capabilities            = Capabilities
 , CapabilitiesGet         = CapabilitiesGet
 , CapabilitiesSet         = CapabilitiesSet
 , ConClose                = ConClose
 , String                  = String
 , Octets                  = Octets
 , Scalar                  = Scalar
 , ObjectFieldAny          = ObjectFieldAny
 , ObjectAny               = ObjectAny
 , ArrayAny                = ArrayAny
 , Any                     = Any
 , Column                  = Column
 , Projection              = Projection
 , Collection              = Collection
 , Limit                   = Limit
 , Order                   = Order
 , UpdateOperation         = UpdateOperation
 , Find                    = Find
 , Insert                  = Insert
 , TypedRow                = TypedRow 
 , Update                  = Update
 , Delete                  = Delete
 , CreateView              = CreateView
 , ModifyView              = ModifyView
 , DropView                = DropView
 , Condition               = Condition
 , ExpectOpen              = ExpectOpen
 , ExpectClose             = ExpectClose
 , Expr                    = Expr
 , Identifier              = Identifier
 , DocumentPathItem        = DocumentPathItem
 , ColumnIdentifier        = ColumnIdentifier
 , FunctionCall            = FunctionCall
 , Operator                = Operator
 , Object                  = Object
 , ObjectField             = ObjectField
 , Array                   = Array
 , FrameType               = FrameType
 , Frame                   = Frame
 , Warning                 = Warning
 , SessionVariableChanged  = SessionVariableChanged
 , SessionStateChanged     = SessionStateChanged
 , FetchDoneMoreOutParams  = FetchDoneMoreOutParams
 , FetchDoneMoreResultsets = FetchDoneMoreResultsets
 , FetchDone               = FetchDone
 , ColumnMetaData          = ColumnMetaData
 , Row                     = Row
 , AuthenticateStart       = AuthenticateStart
 , AuthenticateContinue    = AuthenticateContinue
 , AuthenticateOk          = AuthenticateOk
 , SessReset               = SessReset
 , SessClose               = SessClose
 , StmtExecute             = StmtExecute
 , StmtExecuteOk           = StmtExecuteOk
 , clientmessagetype       = clientmessagetype
 , servermessagetype       = servermessagetype
 , Ok                      = Ok
 , Error                   = Error
}

-- https://stackoverflow.com/a/18694774
function utf8_from(t)
  local bytearr = {}
  for i = 0, t:len()-1 do
    local v = t:get_index(i)
    local utf8byte = v < 0 and (0xff + v + 1) or v
    table.insert(bytearr, string.char(utf8byte))
  end
  return table.concat(bytearr)
end

-- http://lua-users.org/wiki/CommonFunctions
function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function is_num_or_str(v)
  return type(v) == "number" or type(v) == "string"
end

function register_metatable(def_tbl, name)
   local meta = getmetatable(def_tbl)
   meta = meta and meta or {}
   meta["name"] =  name
   meta["__concat"] = function(v1, v2) if is_num_or_str(v1) then return v1 .. name else return name .. v2 end end
   setmetatable(def_tbl, meta)
end

for key, value in pairs(message_table) do
  register_metatable(value, key)
end

function get_table_name(tbl)
  return getmetatable(tbl).name
end

function is_base_message(tbl)
  return get_table_name(tbl) == "clientmessagetype" or getmetatable(tbl).name == "servermessagetype" 
end

-- register field for each message
function register_proto_field(def_tbl) 
  local tbl_name = getmetatable(def_tbl).name
  for key, msg in pairs(def_tbl) do 
    if (type(key) == "number") then
      local nm = def_tbl[key].name
      local proto_field = ProtoField.new (is_base_message(def_tbl) and nm or msg.type .. "." .. nm, nm, ftypes.BYTES)
      f[tbl_name .. "." .. nm] = proto_field
      msg["protofield"] = proto_field
    end
  end 
end

for key, value in pairs(message_table) do
  register_proto_field(value)
end

-- https://developers.google.com/protocol-buffers/docs/encoding
-- | Type | Meaning          | Used For
-- | 0    | Varint           | int32, int64, uint32, uint64, sint32, sint64, bool, enum
-- | 1    | 64-bit           | fixed64, sfixed64, double
-- | 2    | Length-delimited | string, bytes, embedded messages, packed repeated fields
-- | 3    | Start group      | groups (deprecated)
-- | 4    | End group        | groups (deprecated)
-- | 5    | 32-bit           | fixed32, sfixed32, float
function is_varint(v)            return v == 0 end 
function is_64bit(v)             return v == 1 end 
function is_length_delimited(v)  return v == 2 end 
function is_32bit(v)             return v == 3 end 

function get_base_message_table(server_or_client, msg_type_num)
  return server_or_client and servermessagetype[msg_type_num] or clientmessagetype[msg_type_num]
end

function get_message(server_or_client, msg_type_num)
  return message_table[get_message_type(server_or_client, msg_type_num)]
end

function get_message_name(server_or_client, msg_type_num)
  return get_base_message_table(server_or_client, msg_type_num).name
end

function get_message_type(server_or_client, msg_type_num)
  return get_base_message_table(server_or_client, msg_type_num).type
end

function get_message_protofield(server_or_client, msg_type_num)
  return get_base_message_table(server_or_client, msg_type_num).protofield
end

function get_size_type_payload (offset, tvb)
  -- size
  local msg_size
  local payload_len
  -- if state.payload_len == nil then
    if (offset + 4 <= tvb:len()) then
      msg_size = tvb(offset, 4)
      payload_len = msg_size :le_int() - 1
      offset = offset + 4
    else
      msg_size    = nil
      payload_len = nil
    end
  -- type
  local msg_type
  local msg_type_num
  -- if state.msg_type_num == nil then 
    if (offset + 1 <= tvb:len()) then 
      msg_type     = tvb(offset, 1)
      msg_type_num = msg_type :int() 
      offset = offset + 1
    else
      msg_type     = nil 
      msg_type_num = nil 
    end
  -- payload
  local msg_payload 
  if (offset + payload_len <= tvb:len()) then 
    msg_payload = tvb(offset, payload_len) 
  else
    msg_payload = nil
  end
  offset = offset + payload_len
  return offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload
end

-- https://stackoverflow.com/questions/33510736/check-if-array-contains-specific-value
function has_value (tab, val)
  for index, value in ipairs(tab) do
    if value == val then
      return true
    end
  end
  return false
end

function is_terminal(val) 
  return has_value(terminal_type, val)
end

function xproto.dissector(tvb, pinfo, tree) -- tvb = testy vertual tvbfer
  pinfo.cols.protocol = "XPROTO"

  local subtree = tree:add (xproto, tvb())

  local direction = pinfo.src_port == p.server_port
  subtree:append_text (direction and " server -> client " or " client -> server ")

  local offset = 0
  local msg_size, payload_len, msg_type, msg_type_num, msg_payload

  local msg_list = {}

  while offset < tvb:len() do
    local messages = subtree:add (f.message, tvb(offset,5)) -- first 5 bytes (usually size and type) 

    offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload = get_size_type_payload (offset, tvb)

    -- reassemble
    -- https://stackoverflow.com/questions/13138088/how-do-i-reassemble-tcp-packet-in-lua-dissector
    if msg_type == nill or msg_payload == nill then
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT 
      return
    end

    if msg_size then
      if p.show_detail then
        messages
          :add (f.size, msg_size)
          :append_text (string.format(" msg_len (%d) : payload_len (%d)", payload_len+1, payload_len))
      end
    end
    if msg_type then
      local msg_name = get_message_name(direction, msg_type_num)
      table.insert(msg_list, msg_name)
      messages :append_text ("  " .. msg_name)
               :append_text (string.format(" msg_len (%d), payload_len (%d)", payload_len+1, payload_len))
      if p.show_detail then
         messages
           :add (f.tipe, msg_type)
           :append_text (string.format(" (%d) ", msg_type_num))
           :append_text (get_message_name(direction, msg_type_num))
      end
    end
    if msg_payload then 
      local payload = messages:add (get_message_protofield(direction, msg_type_num), msg_payload) 
      payload:append_text (string.format(" length (%d)", msg_payload:len()))
      if msg_payload :len() > 0 then
        
        local next_msg = get_message(direction, msg_type_num)
        process_tree(msg_payload, next_msg, payload)
      end
    end
    -- https://stackoverflow.com/questions/6589617/lua-convert-a-table-into-a-comma-separated-list
    pinfo.columns.info = (direction and "[S->C] " or "[C->S] ") .. table.concat(msg_list, ",")
  end
end

DissectorTable.get("tcp.port"):add(p.server_port, xproto)

-- little ending and 7bit each
function get_length_val(offset, tvb) 
  offset_start = offset
  local b = tvb(offset, 1) -- get one byte
  offset = offset + 1
  local acc, base = get_number(0, 1, b)
  while b:bitfield(0,1) == 1 do
    b = tvb(offset, 1)
    offset = offset + 1
    acc, base = get_number(acc, base, b)
  end
  return b:uint(), acc, offset, (offset - offset_start)
end

-- @param val value to be analyzed.
function get_number(acc, base, val) 
  local acc1 = acc
  for i=7, 1, -1 do                -- ignore MSB
    if val :bitfield(i,1) == 1 then
      acc1 = acc1 + (2^(base-1))
    end
    base = base + 1
  end
  return acc1, base
end

function get_wire_tag(offset, tvb) 
  local key  = tvb(offset, 1) :uint()  -- TODO check length
  local wire = bit32.band(key, 7)      -- TODO check value
  local tag  = bit32.rshift(key,3)     -- TODO check value
  return wire, tag, 1 
end

-- 0  1  2  3  4  5  6  7 
-- 0 -1  1 -2  2 -3  3 -4
function decode_zigzag(v)
  if v % 2 == 0 then
    return (v / 2) 
  else
    return -((v + 1) / 2)
  end
end

function decode_bool(v)
  return v == 0 and "FALSE" or "TRUE"
end

local fmt_field_variant_debug            = "[(%1$d)] wiret_type (%2$d), tag_no (%3$d) value (%4$s) acc (%5$d)"
local fmt_length_delimited_nodata_debug  = "[(%1$d)] wiret_type (%2$d), tag_no (%3$d) length (%4$d) acc(%5$d)"
local fmt_length_delimited_debug         = "[(%1$d)] wiret_type (%2$d), tag_no (%3$d) length (%4$d) acc(%5$d) value (%5$s)"
local fmt_field_variant_detail           = "wire,tag=[%2$d,%3$d], value (%4$s)"
local fmt_field_variant                  = ", val (%4$s)"
local fmt_length_delimited_nodata_detail = "wire,tag=[%2$d,%3$d], length (%5$d)"
local fmt_length_delimited_nodata        = "no data"
local fmt_length_delimited_detail        = "wire,tag=[%2$d,%3$d], length (%5$d) value (%6$s)"
local fmt_length_delimited               = ", val (%6$s)"

-- https://stackoverflow.com/questions/20318698/is-there-a-way-to-specify-the-argument-positions-in-the-format-string-for-strin
local function reorder(fmt, ...)
    local args, order = {...}, {}
    fmt = fmt:gsub('%%(%d+)%$', function(i) table.insert(order, args[tonumber(i)]) return '%' end)
    return string.format(fmt, table.unpack(order))
end

function make_proto_field_varint(parent_tree, pos, tvb, wire_type, tag_no, msg)
  local val, acc, po, read_size = get_length_val(pos, tvb)
  pos = pos + read_size
  item = parent_tree:add(msg[tag_no].protofield, tvb(pos - read_size , read_size))
  -- data conversion !!!!!
  -- TODO check type of a value.
  if msg[tag_no].converter            then
    val = msg[tag_no].converter(acc) 
  elseif msg[tag_no].type_fun         then  -- dynamic type change.
    val = msg[tag_no].type_fun(acc)
  elseif msg[tag_no].type == "bool"   then
    val = decode_bool(acc)
  elseif msg[tag_no].type == "sint64" then
    val = decode_zigzag(acc)
  else
    val = acc -- this type is numeric
  end
  if p.show_detail then
    item :add (reorder(fmt_field_variant_detail , po, wire_type, tag_no, tostring(val), acc))
  else
    parent_tree:append_text (reorder(fmt_field_variant , po, wire_type, tag_no, tostring(val), acc))
  end

  return read_size 
end

function make_proto_length_delimited(parent_tree, pos, tvb, wire_type, tag_no, msg)
  local pos_start = pos
  local le, acc, po, readsize = get_length_val(pos, tvb)
  pos = pos + readsize

  local type = msg[tag_no].type 
  if is_terminal(type) then
    if acc == 0 then
      if p.show_detail then
        parent_tree
          :add(msg[tag_no].protofield)
          :add (reorder(fmt_length_delimited_nodata_detail, po, wire_type, tag_no, le, acc, va))
      else
        parent_tree :append_text(reorder(fmt_length_delimited_nodata, po, wire_type, tag_no, le, acc, va))
      end
    else
      local next_tvb = tvb(pos, acc)
      -- data conversion !!!!!
      local va
      if getmetatable(msg).name == "String" then
        va = utf8_from(tvb(pos, acc) : bytes())
      else
        va = tvb(pos, acc) : string()
      end
      pos = pos + acc
      if p.show_detail then
         parent_tree
           :add(msg[tag_no].protofield, next_tvb)
           :add (reorder(fmt_length_delimited_detail , po, wire_type, tag_no, le, acc, va))
      else
        parent_tree :append_text(reorder(fmt_length_delimited , po, wire_type, tag_no, le, acc, va))
      end
     end
  else 
    -- recursive
    local next_tvb = tvb(pos, acc)
    pos = pos + acc
    local next_msg = message_table[msg[tag_no].type]
    local next_subtree = parent_tree:add(msg[tag_no].protofield, next_tvb)
    process_tree(next_tvb, next_msg, next_subtree) 
    if msg[tag_no].clear then
      msg[tag_no].clear()
    end
  end
  return pos - pos_start
end

-- analyze data recursivly.
function process_tree(tvb, msg, subtree)
  local l_pos     = 0
  local l_tvb     = tvb
  local l_msg     = msg
  local l_msg_len = tvb:len()
  local l_subtree = subtree

  while (l_pos < l_msg_len) do
     local l_wire_type, l_tag_no, read_size = get_wire_tag(l_pos, l_tvb) 
     l_pos = l_pos + read_size 

     if is_varint(l_wire_type) then
        local read_size = make_proto_field_varint(l_subtree, l_pos, l_tvb, l_wire_type, l_tag_no, l_msg)
        l_pos = l_pos + read_size 

     elseif is_length_delimited(l_wire_type) then
        local read_size =  make_proto_length_delimited(l_subtree, l_pos, l_tvb, l_wire_type, l_tag_no, l_msg)
        l_pos = l_pos + read_size 

     end
  end
end

--[[ What to do

TODO decode column data based on resultset
--]]

--[[ sample packets

packet test data              | capture file                     | statement
-------------------------------------------------------------------------------------------------------------
login falirue                 | mysqlsh_password_invalid.pcapng  |
SQL                           | -                                | -
 Select                       | sql_select_01.pcapng             | select * from country limit 1;
                              | sql_select_02.pcapng             | select * from  countrylanguage limit 1;
 Insert                       | sql_insert.pcapng                | insert into foo(id,v) values(123, 'abc');
 Update                       | sql_update.pcapng                | update foo set v='xyz' where id=123;
 Delete                       | sql_delete.pcapng                | delete from foo;
  SQL syntacs error           | sql_syntax_error.pcapng          | updat foo set v='xyz' where id=123;
  select error (table)        | sql_select_error.pcapng          | select * from country__ limit 1;
  insert error (duplication)  | sql_insert_duplicate_key.pcapng  | insert into bazz values(1);
 warnning
  insert (out of range)       TODO
 Management                   | -                                | - 
  show schemas                | sql_show_schemas.pcapng          |
  use world_x                 | sql_use_world_x.pcapng           |
CRUD                          | -                                | -
 Read                         | crud_find_01.pcapng              | db.countryinfo.find().limit(1)
                              | crud_find_02.pcapng              | db.countryinfo.find('$.Name = "Aruba"')
                              | crud_find_03.pcapng              | db.countryinfo.find('$.geography.Continent = "North America"').fields("count('$._id') as count")
                              | crud_find_04.pcapng              | db.countryinfo.find().fields(["$.geography.Continent as continent", "count('$._id') as count"]).groupBy('$.geography.Continent')
                              | crud_find_05.pcapng              | db.countryinfo.find('$.geography.Continent = :param1').fields("count('$._id') as count").bind('param1', 'North America') 
 Create                       | crud_insert_01.pcapng            | products.add ({" name":"bananas ", " color":"yellow "}).execute(); 
                              | crud_insert_02.pcapng            | products.add ([{"x":1},{"x":2}]).execute();
 Update                       | crud_update_01.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").set("color", "red")
                              | crud_update_02.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").set("price", 1000)
                              | crud_update_03.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").unset("price")
                              | crud_update_04.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").set("$.quality", ['c','d'])
                              | crud_update_05.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").arrayInsert("$.quality[1]", 'b')
                              | crud_update_06.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").arrayDelete("$.quality[0]")
 Delete                       | crud_delete_01.pcapng            | products.remove("$._id = '5e76990f3ae6e711938388d17dfe8291'") 
 null                         | null_insert_01.pcapng            | tbl.insert(['id', 'f1']).values(1,null)
                              | null_select_01.pcapng            | tbl.select(['id', 'f1']).where("f1 is null")
 error                        | -                                | -
  select error                | curd_error_find_01.pcapng        | db.countryinfo.find().fields(["$.geography.Continent as continent"]).groupBy('$.geography.Continent').having("count('$._id') < 10")
Schema                        | -                                | -
 getSchema                    | crud_getschema.pcapng            | db = session.getSchema("world_x")
 getSchema  (create )         | mysqlsh_session_getschema.pcapng | mydb = session.getSchema("mydb")
Collection                    | -                                | -
 create                       | mysqlsh_create_collection.pcapng | mydb.createCollection("products")
 get                          | mysqlsh_get_collection.pcapng    | mydb.getCollection("products")
Connection                    | -                                | -
 Open                         | mysqlsh_session_open.pcapng      | mysqlx.getNodeSession({'host':'localhost', 'port':8000, 'dbUser':'root', 'dbPassword':'root'})
 Close                        | mysqlsh_session_close.pcapng     | session.close()
Index                         | -                                | -
 create                       | mysqlsh_create_index_01.pcapng   | products.createIndex("my_index").field("$.name", "text(30)", false).execute()
 delete                       | mysqlsh_delete_index.pcapng      | products.dropIndex("my_index").execute()
Pipeline                      | pipeline_open.pcapng                               |
                              | pipeline_5_inserts_3rd_failure_nomal.pcapng        |
                              | pipeline_5_inserts_3rd_failure_nomal1.pcapng       |
                              | pipeline_5_inserts_3rd_failure_no_error.pcapng     |
                              | pipeline_5_inserts_3rd_failure_no_errori1.pcapng   |
--]]

--[[ just for debug

info(string.format("pos=%d, len=%d " , l_pos, len))
info(string.format("@@ wire_type=%d, tag_no=%d", wire_type, tag_no))
--]]

--[[ reference for reading binary of protocol buffer. 

08 0000 1000  wire=0, tag=1      
0a 0000 1010  wire=2, tag=1
12 0001 0010  wire=2, tag=2
1a 0001 1010  wire=2, tag=3
22 0010 0010  wire=2, tag=4
2a 0010 1010  wire=2, tag=5
32 0011 0010  wire=2, tag=6
3a 0011 1010  wire=2, tag=7
40 0100 0000  wire=0, tag=8       
48 0100 1000  wire=0, tag=9
50 0101 0000  wire=0, tag=10
58 0101 1000  wire=0, tag=11
60 0110 0000  wire=0, tag=12
--]]

--[[ a manual decoding example

0000  08 07 12 03 64 6f 63 1a  03 64 6f 63 22 0b 63 6f   ....doc. .doc".co
      **    **             **  ~~          ** ~~
0010  75 6e 74 72 79 69 6e 66  6f 2a 0b 63 6f 75 6e 74   untryinf o*.count
                                  ** ~~             
0020  72 79 69 6e 66 6f 32 07  77 6f 72 6c 64 5f 78 3a   ryinfo2. world_x:
                        ** ~~                       **
0030  03 64 65 66 40 3f 48 00  50 ff ff ff ff 0f 58 00   .def@?H. P.....X.
      ~~          **    **     **                **
0040  60 02  
      ** 

[S-C] a Capability of Capabilities

Capabilities

+Capability w2 
|      
|     +string        +Any w2
|     |              | 
|     |              |     +Type +Scalar w2
|     |              |     |     |     
|     |              |     |     |     +Type 
|     |              |     |     |     |      
|     |              |     |     |     |      +bool w2
|     |              |     |     |     |      |
0a 0f 0a 03 74 6c 73 12 08 08 01 12 04 08 07 40 00
** ~~ ** ~~          ** ~~ **    ** ~~ **    **

--]]

--[[
decode zigzag 
e834
1110100000110100
11101000 00110100
00110100 11101000 
0110100 1101000 
01101001101000 
6760
3380
--]]
