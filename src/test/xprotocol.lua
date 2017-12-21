-- naminig rule
-- identifier  -->  word1 .. "_" .. word2

-- TODO decode column data based on resultset

local xproto = Proto ("XProtocol", "X Protocol Dissector");

function xproto.init () 
  -- init_state()
end

-- Preferences
local p = xproto.prefs
p.server_port = Pref.uint ("server port", 8000, "server port number") -- TODO 33060 should be default

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
  ConditionOperation = {
    [0] = "EXPECT_OP_SET"
   ,[1] = "EXPECT_OP_UNSET"
  }
  , [1] = {attr = "required", type = "uint32",             name="condition_key",   tag = 1}
  , [2] = {attr = "optional", type = "bytes",              name="condition_value", tag = 2}
  , [3] = {attr = "optional", type = "ConditionOperation", name="op",              tag = 3}
  ,enum_fun = function(v) return Condition.ConditionOperation[v] end
}
Condition[3].converter = Condition.enum_fun 
ExpectOpen = {
  CtxOperation = {
    [0] = "EXPECT_CTX_COPY_PREV"
   ,[1] = "EXPECT_CTX_EMPTY"
  }
 ,[1] = {attr = "optional" , type = "CtxOperation" , name="op"   , tag = 1}
 ,[2] = {attr = "repeated" , type = "Condition"    , name="cond" , tag = 2}
 ,enum_fun = function(v) return Open.CtxOperation[v] end
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
 ,enum_fun = function(v) return ColumnMetaData.FieldType[v] end
}
ColumnMetaData[1].converter = ColumnMetaData.enum_fun 
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
  , [15] = {name = "RESULTSET_FETCH_SUSPENDED",            type = "nil",                      } -- TODO
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
 , Open                    = Open
 , Condition               = Condition
 , Close                   = Close
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
      messages
        :add (f.size, msg_size) 
        :append_text (string.format(" msg_len (%d) : payload_len (%d)", payload_len+1, payload_len))
    end
    if msg_type then
      messages :append_text ("  " .. get_message_name(direction, msg_type_num))
      messages 
        :add (f.tipe, msg_type) 
        :append_text (string.format(" (%d) ", msg_type_num))
        :append_text (get_message_name(direction, msg_type_num))
    end
    if msg_payload then 
      local payload = messages:add (get_message_protofield(direction, msg_type_num), msg_payload) 
      payload:append_text (string.format(" length (%d)", msg_payload:len()))
      if msg_payload :len() > 0 then
        
        local next_msg = get_message(direction, msg_type_num)
        process_tree(msg_payload, next_msg, payload)
      end
    end
    -- 
    -- update_state(msg_size, payload_len, msg_type, msg_type_num, msg_payload)
  end
end

DissectorTable.get("tcp.port"):add(p.server_port, xproto)

-- little ending and 7bit each
function get_length_val(offset, tvb) 
  offset_start = offset
  local b = tvb(offset, 1)
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
  for i=7, 1, -1 do                -- ignore MSB
    if val :bitfield(i,1) == 1 then
      acc = acc + (2^(base-1))
    end
    base = base + 1
  end
  return acc, base
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

function make_proto_field_varint(parent_tree, pos, tvb, wire_type, tag_no, msg)
  local val, acc, po, read_size = get_length_val(pos, tvb)
  pos = pos + read_size
  item = parent_tree:add(msg[tag_no].protofield, tvb(pos - read_size , read_size))
  -- TODO check type of a value.
  if msg[tag_no].converter          then  -- enum
    val = msg[tag_no].converter(acc) 
  elseif msg[tag_no].type_fun       then
    val = msg[tag_no].type_fun(acc)
  elseif msg[tag_no].type == "bool" then
    val = decode_bool(val)
  end
  item :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) value (%s) acc (%d)", po, wire_type, tag_no, tostring(val), acc))
  return read_size 
end

function make_proto_length_delimited(parent_tree, pos, tvb, wire_type, tag_no, msg)
  local pos_start = pos
  local le, acc, po, readsize = get_length_val(pos, tvb)
  pos = pos + readsize

  local type = msg[tag_no].type 
  if is_terminal(type) then
    if acc == 0 then
      parent_tree
        :add(msg[tag_no].protofield)
        :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) length (%d) acc(%d)"
                      , po, wire_type, tag_no, le, acc))
    else
      local next_tvb = tvb(pos, acc)
      local va = tvb(pos, acc) : string()
      pos = pos + acc
      parent_tree
        :add(msg[tag_no].protofield, next_tvb)
        :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) length (%d) acc(%d) value (%s)"
                      , po, wire_type, tag_no, le, acc, va))
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

-- packet test data              | capture file                     | statement
-- -------------------------------------------------------------------------------------------------------------
-- login falirue                 | mysqlsh_password_invalid.pcapng  |
-- SQL                           | -                                | -
--  Select                       | sql_select_01.pcapng             | select * from country limit 1;
--                               | sql_select_02.pcapng             | select * from  countrylanguage limit 1;
--  Insert                       | sql_insert.pcapng                | insert into foo(id,v) values(123, 'abc');
--  Update                       | sql_update.pcapng                | update foo set v='xyz' where id=123;
--  Delete                       | sql_delete.pcapng                | delete from foo;
--   SQL syntacs error           | sql_syntax_error.pcapng          | updat foo set v='xyz' where id=123;
--   select error (table)        | sql_select_error.pcapng          | select * from country__ limit 1;
--   insert error (duplication)  | sql_insert_duplicate_key.pcapng  | insert into bazz values(1);
--  warnning
--   insert (out of range)       TODO
--  Management                   | -                                | - 
--   show schemas                | sql_show_schemas.pcapng          |
--   use world_x                 | sql_use_world_x.pcapng           |
-- CRUD                          | -                                | -
--  Read                         | crud_find_01.pcapng              | db.countryinfo.find().limit(1)
--                               | crud_find_02.pcapng              | db.countryinfo.find('$.Name = "Aruba"')
--                               | crud_find_03.pcapng              | db.countryinfo.find('$.geography.Continent = "North America"').fields("count('$._id') as count")
--                               | crud_find_04.pcapng              | db.countryinfo.find().fields(["$.geography.Continent as continent", "count('$._id') as count"]).groupBy('$.geography.Continent')
--                               | crud_find_05.pcapng              | db.countryinfo.find('$.geography.Continent = :param1').fields("count('$._id') as count").bind('param1', 'North America') 
--  Create                       | crud_insert_01.pcapng            | products.add ({" name":"bananas ", " color":"yellow "}).execute(); 
--                               | crud_insert_02.pcapng            | products.add ([{"x":1},{"x":2}]).execute();
--  Update                       | crud_update_01.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").set("color", "red")
--                               | crud_update_02.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").set("price", 1000)
--                               | crud_update_03.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").unset("price")
--                               | crud_update_04.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").set("$.quality", ['c','d'])
--                               | crud_update_05.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").arrayInsert("$.quality[1]", 'b')
--                               | crud_update_06.pcapng            | products.modify("$._id = '5e76990f3ae6e711938388d17dfe8291'").arrayDelete("$.quality[0]")
--  Delete                       | crud_delete_01.pcapng            | products.remove("$._id = '5e76990f3ae6e711938388d17dfe8291'") 
--  error                        | -                                | -
--   select error                | curd_error_find_01.pcapng        | db.countryinfo.find().fields(["$.geography.Continent as continent"]).groupBy('$.geography.Continent').having("count('$._id') < 10")
-- Schema                        | -                                | -
--  getSchema                    | crud_getschema.pcapng            | db = session.getSchema("world_x")
--  getSchema  (create )         | mysqlsh_session_getschema.pcapng | mydb = session.getSchema("mydb")
-- Collection                    | -                                | -
--  create                       | mysqlsh_create_collection.pcapng | mydb.createCollection("products")
--  get                          | mysqlsh_get_collection.pcapng    | mydb.getCollection("products")
-- Connection                    | -                                | -
--  Open                         | mysqlsh_session_open.pcapng      | mysqlx.getNodeSession({'host':'localhost', 'port':8000, 'dbUser':'root', 'dbPassword':'root'})
--  Close                        | mysqlsh_session_close.pcapng     | session.close()
-- Index                         | -                                | -
--  create                       | mysqlsh_create_index_01.pcapng   | products.createIndex("my_index").field("$.name", "text(30)", false).execute()
--  delete                       | mysqlsh_delete_index.pcapng      | products.dropIndex("my_index").execute()
-- Pipeline                      TODO

-- info(string.format("pos=%d, len=%d " , l_pos, len))
-- info(string.format("@@ wire_type=%d, tag_no=%d", wire_type, tag_no))

--
-- 0a 0000 1010 wire=2, tag=1
-- cf 1100 1111 
-- 02 0000 0010  -> 10 1001111

-- 0000   0a cf 02 7b 22 47 4e 50 22 3a 20 38 32 38 2c 20
--        
-- 0010   22 5f 69 64 22 3a 20 22 41 42 57 22 2c 20 22 4e
-- 0020   61 6d 65 22 3a 20 22 41 72 75 62 61 22 2c 20 22
-- 0030   49 6e 64 65 70 59 65 61 72 22 3a 20 6e 75 6c 6c
-- 0040   2c 20 22 67 65 6f 67 72 61 70 68 79 22 3a 20 7b
-- 0050   22 52 65 67 69 6f 6e 22 3a 20 22 43 61 72 69 62
-- 0060   62 65 61 6e 22 2c 20 22 43 6f 6e 74 69 6e 65 6e
-- 0070   74 22 3a 20 22 4e 6f 72 74 68 20 41 6d 65 72 69
-- 0080   63 61 22 2c 20 22 53 75 72 66 61 63 65 41 72 65
-- 0090   61 22 3a 20 31 39 33 7d 2c 20 22 67 6f 76 65 72
-- 00a0   6e 6d 65 6e 74 22 3a 20 7b 22 48 65 61 64 4f 66
-- 00b0   53 74 61 74 65 22 3a 20 22 42 65 61 74 72 69 78
-- 00c0   22 2c 20 22 47 6f 76 65 72 6e 6d 65 6e 74 46 6f
-- 00d0   72 6d 22 3a 20 22 4e 6f 6e 6d 65 74 72 6f 70 6f
-- 00e0   6c 69 74 61 6e 20 54 65 72 72 69 74 6f 72 79 20
-- 00f0   6f 66 20 54 68 65 20 4e 65 74 68 65 72 6c 61 6e
-- 0100   64 73 22 7d 2c 20 22 64 65 6d 6f 67 72 61 70 68
-- 0110   69 63 73 22 3a 20 7b 22 50 6f 70 75 6c 61 74 69
-- 0120   6f 6e 22 3a 20 31 30 33 30 30 30 2c 20 22 4c 69
-- 0130   66 65 45 78 70 65 63 74 61 6e 63 79 22 3a 20 37
-- 0140   38 2e 34 30 30 30 30 31 35 32 35 38 37 38 39 7d
-- 0150   7d 00

-- VarInt   = 0
-- Bit64    = 1
-- LenDelim = 2
-- Bit32    = 5
-- 
--     0-tag(4)-wire(3)
--
--  08 0000 1000  wire=0, tag=1      
--  12 0001 0010  wire=2, tag=2
--  1a 0001 1010  wire=2, tag=3
--  22 0010 0010  wire=2, tag=4
--  2a 0010 1010  wire=2, tag=5
--  32 0011 0010  wire=2, tag=6
--  3a 0011 1010  wire=2, tag=7
--  40 0100 0000  wire=0, tag=8       
--  48 0100 1000  wire=0, tag=9
--  50 0101 0000  wire=0, tag=10
--  58 0101 1000  wire=0, tag=11
--  60 0110 0000  wire=0, tag=12
--
--  0a 0000 1010  wire0,  tag=2

--  3f 0011 1111
--
--  ff ff ff ff 0f = 11111111 11111111 11111111 11111111 00001111
--                   0000 0000 1111 1111 1111 1111 1111 1111 1111 1111 
-- 
-- 0000  08 07 12 03 64 6f 63 1a  03 64 6f 63 22 0b 63 6f   ....doc. .doc".co
--       **    **             **  ~~          ** ~~
-- 0010  75 6e 74 72 79 69 6e 66  6f 2a 0b 63 6f 75 6e 74   untryinf o*.count
--                                   ** ~~             
-- 0020  72 79 69 6e 66 6f 32 07  77 6f 72 6c 64 5f 78 3a   ryinfo2. world_x:
--                         ** ~~                       **
-- 0030  03 64 65 66 40 3f 48 00  50 ff ff ff ff 0f 58 00   .def@?H. P.....X.
--       ~~          **    **     **                **
-- 0040  60 02  
--       ** 

-- [S-C] a Capability of Capabilities
--
-- Capabilities
--
-- +Capability w2 
-- |      
-- |     +string        +Any w2
-- |     |              | 
-- |     |              |     +Type +Scalar w2
-- |     |              |     |     |     
-- |     |              |     |     |     +Type 
-- |     |              |     |     |     |      
-- |     |              |     |     |     |      +bool w2
-- |     |              |     |     |     |      |
-- 0a 0f 0a 03 74 6c 73 12 08 08 01 12 04 08 07 40 00
-- ** ~~ ** ~~          ** ~~ **    ** ~~ **    **
--
-- 0a 0000 1010 wire=2, tag=1
-- 12 0001 0010 wire=2, tag=2
-- 08 0000 1000 wire=0, tag=1      
-- 40 0100 0000 wire=0, tag=8       
-- 0f -> 15
--
-- 
-- 

