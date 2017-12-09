require "alien"

-- naminig rule
-- identifier  -->  word1 .. "_" .. word2


local xproto = Proto ("XProtocol", "X Protocol Dissector");

local packet_cnt

function xproto.init () 
  packet_cnt = 0
  initState()
end

-- Preferences
local p = xproto.prefs

p.server_port = Pref.uint ("server port", 8000, "server port number") -- TODO 33060 should be default


-- Fields
local f = xproto.fields

f.message   = ProtoField.bytes  ("XProtocol.message"   , "Message"    )
f.size      = ProtoField.bytes  ("XProtocol.size"      , "Size"       )
f.tipe      = ProtoField.bytes  ("XProtocol.type"      , "Type"       )
f.payload   = ProtoField.bytes  ("XProtocol.payload"   , "Payload"    )
f.pbitem    = ProtoField.bytes  ("XProtocol.pbitem"    , "proto item" )

-- state between packets -- TODO not good state management, we need to consider each item is divided between packet.
state = {
    payload_len  = nil
  , msg_type_num = nil
  , msg_payload  = nil
}

-- mysql_connection.proto
Capability = {
  [1] = {attr = "required", type = "string", name = "name",  tag = 1}
 ,[2] = {attr = "required", type = "Any",    name = "Capability.value", tag = 2}
}
Capabilities = {
  [1] = {attr = "repeated", type = "Capability", name="capabilities", tag  = 1}
}
CapabilitiesGet = {
}
CapabilitiesSet = {
  [1] = {attr = "repeated", type = "Capabilities", name="capabilities", tag  = 1}
}
close = {
}
-- mysql_datatypes.proto
String = {
   [1] = {attr = "required" , type = "bytes" , name="String.value" , tag = 1}
  ,[2] = {attr = "optional" , type = "uint64", name="collation", tag = 2}
}
Octets = {
   [1] = {attr = "required" , type = "bytes",  name = "value",        tag  = 1}
  ,[2] = {attr = "optional" , type = "uint32", name = "content_type", tag  = 2}
}

--  enum Type {
--    V_SINT = 1;
--    V_UINT = 2;
--    V_NULL = 3;
--    V_OCTETS = 4;
--    V_DOUBLE = 5;
--    V_FLOAT = 6;
--    V_BOOL  = 7;
--    V_STRING  = 8;
--  };

Scalar = {
    [1] = {attr = "required" , type = "Type"   , name = "Scalar.type", tag   = 1}
   ,[2] = {attr = "optional" , type = "sint64" , name = "v_signed_int", tag   = 2}
   ,[3] = {attr = "optional" , type = "uint64" , name = "v_unsigned_int", tag   = 3}
   ,[5] = {attr = "optional" , type = "Octets" , name = "v_octets", tag   = 5}
   ,[6] = {attr = "optional" , type = "double" , name = "v_double", tag   = 6}
   ,[7] = {attr = "optional" , type = "float"  , name = "v_float", tag   = 7}
   ,[8] = {attr = "optional" , type = "bool"   , name = "v_bool", tag   = 8}
   ,[9] = {attr = "optional" , type = "String" , name = "v_string", tag   = 9}
}

ObjectField = {
   [1] = {attr = "required" , type = "string", name = "key", tag   = 1}
  ,[2] = {attr = "required" , type = "Any", name = "value", tag   = 2}
}

Object = {
  [1] = {attr = "repeated" , type = "ObjectField", name = "fld", tag   = 1}
}

Array = {
  [1] = {attr = "repeated" , type = "Any", name = "value", tag   = 1}
}

Any = {
--   enum Type {
--     SCALAR = 1
--     OBJECT = 2
--     ARRAY  = 3
--   }
    [1] = {attr = "required" , type = "Type",   name = "Any.type",   tag = 1}
  , [2] = {attr = "optional" , type = "Scalar", name = "scalar", tag = 2}
  , [3] = {attr = "optional" , type = "Object", name = "obj",    tag = 3}
  , [4] = {attr = "optional" , type = "Array",  name = "array",  tag = 4}
}

--
ColumnMetaData = {
    [1]  = {type = "FieldType", name = "type"             , tag=1 }
  , [2]  = {type = "bytes",     name = "name"             , tag=2 }
  , [3]  = {type = "bytes",     name = "original_name"    , tag=3 }
  , [4]  = {type = "bytes",     name = "table"            , tag=4 }
  , [5]  = {type = "bytes",     name = "original_table"   , tag=5 }
  , [6]  = {type = "bytes",     name = "schema"           , tag=6 }
  , [7]  = {type = "bytes",     name = "catalog"          , tag=7 }
  , [8]  = {type = "uint64",    name = "collation"        , tag=8 }
  , [9]  = {type = "uint32",    name = "fractional_digits", tag=9 }
  , [10] = {type = "uint32",    name = "length"           , tag=10}
  , [11] = {type = "uint32",    name = "flags"            , tag=11}
  , [12] = {type = "uint32",    name = "content_type"     , tag=12}
} 
-- message_table
message_table = {
    Capability      = Capability
  , Capabilities    = Capabilities
  , CapabilitiesGet = CapabilitiesGet
  , CapabilitiesPut = CapabilitiesPut
  , ColumnMetaData  = ColumnMetaData 
  , String = String
  , Octets = Octets
  , Scalar = Scalar
  , ObjectField = ObjectField
  , Object = Object
  , Array = Array
  , Any = Any
}


--
clientmessagetype = {
   [1]  = {name = "CON_CAPABILITIES_GET" , definition = CapabilitiesGet }
  ,[2]  = {name = "CON_CAPABILITIES_SET" , definition = CapabilitiesSet }
  ,[3]  = {name = "CON_CLOSE" , definition = nil }
  ,[4]  = {name = "SESS_AUTHENTICATE_START" , definition = nil }
  ,[5]  = {name = "SESS_AUTHENTICATE_CONTINUE" , definition = nil }
  ,[6]  = {name = "SESS_RESET" , definition = nil }
  ,[7]  = {name = "SESS_CLOSE" , definition = nil }
  ,[12] = {name = "SQL_STMT_EXECUTE" , definition = nil }
  ,[17] = {name = "CRUD_FIND" , definition = nil }
  ,[18] = {name = "CRUD_INSERT" , definition = nil }
  ,[19] = {name = "CRUD_UPDATE" , definition = nil }
  ,[20] = {name = "CRUD_DELETE" , definition = nil }
  ,[24] = {name = "EXPECT_OPEN" , definition = nil }
  ,[25] = {name = "EXPECT_CLOSE" , definition = nil }
  ,[30] = {name = "CRUD_CREATE_VIEW" , definition = nil }
  ,[31] = {name = "CRUD_MODIFY_VIEW" , definition = nil }
  ,[32] = {name = "CRUD_DROP_VIEW" , definition = nil }
}
--
servermessagetype = {
   [0]  = {name = "OK" , definition = nil  }
  ,[1]  = {name = "ERROR" , definition = nil  }
  ,[2]  = {name = "CONN_CAPABILITIES" , definition = Capabilities }
  ,[3]  = {name = "SESS_AUTHENTICATE_CONTINUE" , definition = nil  }
  ,[4]  = {name = "SESS_AUTHENTICATE_OK" , definition = nil  }
  ,[11] = {name = "NOTICE" , definition = nil  }
  ,[12] = {name = "RESULTSET_COLUMN_META_DATA" , definition = ColumnMetaData }
  ,[13] = {name = "RESULTSET_ROW" , definition = nil  }
  ,[14] = {name = "RESULTSET_FETCH_DONE" , definition = nil  }
  ,[15] = {name = "RESULTSET_FETCH_SUSPENDED" , definition = nil  }
  ,[16] = {name = "RESULTSET_FETCH_DONE_MORE_RESULTSETS" , definition = nil  }
  ,[17] = {name = "SQL_STMT_EXECUTE_OK" , definition = nil  }
  ,[18] = {name = "RESULTSET_FETCH_DONE_MORE_OUT_PARAMS" , definition = nil  }
} 

function register_proto_field(def_tbl) 
  for key,value in pairs(def_tbl) do 
     local nm = def_tbl[key].name
     ff = ProtoField.new ("x." .. nm, nm, ftypes.BYTES)
     f[def_tbl[key].name] = ff
     def_tbl[key]["protofield"] = ff
  end 
end

-- register field for each message
register_proto_field(ColumnMetaData)
register_proto_field(CapabilitiesGet)
register_proto_field(CapabilitiesSet)
register_proto_field(Capabilities)
register_proto_field(Capability)
register_proto_field(String)
register_proto_field(Octets)
register_proto_field(Scalar)
register_proto_field(ObjectField)
register_proto_field(Object)
register_proto_field(Array)
register_proto_field(Any)

function get_server_or_client_msg(server_or_client, msg_type_no, tag_no) 
  local msgtbl = server_or_client and servermessagetype or clientmessagetype 
  if msgtbl == nil then
    return nil 
  end
  return msgtbl[msg_type_no]
end

function get_proto_field(server_or_client, msg_type_no, tag_no) 
  info(string.format("[%s] msg_type_no(%d) tag_no(%d)",(server_or_client and "s-c" or "c->s"), msg_type_no, tag_no))
  local msgtbl = server_or_client and servermessagetype or clientmessagetype 
  if msgtbl == nil then
    info("no msgtbl")
    return f.pbitem
  end
  local msg_tbl_item = msgtbl[msg_type_no]["definition"]
  if msg_tbl_item == nil then
    info("no definition")
    return f.pbitem
  end
  local proto_field = msg_tbl_item[tag_no]["protofield"]
  if proto_field == nil then
    info("no protofield")
    return f.pbitem
  end
  return proto_field 
end

function get_message_name(server_or_client, msg_type_num)
  return (tostring(server_or_client and servermessagetype[msg_type_num].name or clientmessagetype[msg_type_num].name))
end

--
--
--

function getMessageParts (offset, tvb)
  -- size
  local msg_size
  local payload_len
  if state.payload_len == nil then
    if (offset + 4 <= tvb:len()) then
      msg_size = tvb(offset, 4)
      payload_len = msg_size :le_int() - 1
      offset = offset + 4
    else
      msg_size    = nil
      payload_len = nil
    end
  else 
    msg_size    = nil
    payload_len = state.payload_len 
  end
  -- type
  local msg_type
  local msg_type_num
  if state.msg_type_num == nil then 
    if (offset + 1 <= tvb:len()) then 
      msg_type     = tvb(offset, 1)
      msg_type_num = msg_type :int() 
      offset = offset + 1
    else
      msg_type     = nil 
      msg_type_num = nil 
    end
  else
    msg_type     = nil 
    msg_type_num = state.msg_type_num
  end
  -- payload
  local msg_payload 
  if (offset + payload_len <= tvb:len()) and state.payload == nil then 
    msg_payload = tvb(offset, payload_len) 
  else
    msg_payload = nil
  end
  offset = offset + payload_len
  return offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload
end

terminal_type = {
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
  ,"Scalar.type"
}

-- https://stackoverflow.com/questions/33510736/check-if-array-contains-specific-value
function has_value (tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end
    return false
end

function isTerminal(val) 
  return has_value(terminal_type, val)
end

info ("================================================================")
info (" start" )
info ("================================================================")

--
-- dissector
--
function xproto.dissector (tvb, pinfo, tree) -- tvb = testy vertual tvbfer
  pinfo.cols.protocol = "XPROTO"
  packet_cnt = packet_cnt + 1

  local subtree = tree:add (xproto, tvb())

  local direction = (pinfo.src_port == p.server_port) and true or false
  subtree:append_text (direction and " server -> client " or " client -> server ")

  local offset = 0
  local msg_size, payload_len, msg_type, msg_type_num, msg_payload

  while offset < tvb:len() do
    messages = subtree:add (f.message, tvb(offset,5)) -- first 5 bytes (usually size and type) 
    offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload = getMessageParts (offset, tvb)
    -- info (string.format("**payload_len=%d, msg_type_num=%d, msg_payload=%s", payload_len, msg_type_num, msg_payload))
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
      payload = messages:add (f.payload, msg_payload) 
      payload:append_text (string.format(" length (%d)", msg_payload:len()))
      if msg_payload :len() > 0 then
        po = 0
        while po < msg_payload :len() do
          item_offset = po
          wiretype , tagno, po = getwiretag(po, msg_payload)
          if (wiretype == 0) then
            val, acc, po, readsize = getLengthVal(po, msg_payload)
           
            ff = get_proto_field(direction, msg_type_num, tagno)
            item = payload:add(ff, msg_payload(item_offset, 1 + readsize))
            item :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) value (%d) acc (%d)"
                         , po, wiretype, tagno, val, acc))

          elseif (wiretype == 2) then
            le, acc, po, readsize = getLengthVal(po, msg_payload)
            va = msg_payload(po, acc) : string()
            po = po + acc

            ff = get_proto_field(direction, msg_type_num, tagno)
            item = payload:add(ff , msg_payload(item_offset, 1 + readsize + acc))
            item :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) length (%d) acc(%d) value (%s)"
                         , po, wiretype, tagno, le, acc, va))
            -- recursive
            local next_tvb = msg_payload(item_offset + 1 + readsize, acc)
            local next_msg = get_server_or_client_msg(direction, msg_type_num, tagno)
            next_msg =  Capability -- debug
            processTree(next_tvb, next_msg, item, acc)
            
          end
        end
      end
    end
    updateState(msg_size, payload_len, msg_type, msg_type_num, msg_payload)
  end
end

-- lettle ending and 7bit each
function getLengthVal(offset, tvb) 
  offsetstart = offset
  b = tvb(offset, 1)
  offset = offset + 1
  acc, base = getnumber(0, 1, b)
  -- info(string.format("acc (%d), (%d), base (%d), bitfield (%d)", b:uint(), acc, base, b:bitfield(0,1)))
  -- info( b:bitfield(0,1) == 1)
  while b:bitfield(0,1) == 1 do
    b = tvb(offset, 1)
    offset = offset + 1
    acc, base = getnumber(acc, base, b)
    -- info(string.format("acc2 (%d), base (%d)", acc, base))
  end
  return b:uint(), acc, offset, (offset - offsetstart)
end

-- @param val value to be analyzed.
function getnumber(acc, base, val) 
  for i=7, 1, -1 do                -- ignore MSB
    if val :bitfield(i,1) == 1 then
      acc = acc + (2^(base-1))
    end
    base = base + 1
  end
  return acc, base
end

function getwiretag(offset, tvb) 
  key  = tvb(offset, 1) :uint()  -- TODO check length
  wire = bit32.band(key, 7)      -- TODO check value
  tag  = bit32.rshift(key,3)     -- TODO check value
  offset = offset + 1
  return wire, tag, offset
end

function zigzag(tvb) -- TODO not working
  v = tvb :int()
  a = bit32.rshift(v,1)
  b = bit32.band  (v,1)
  return bit32.bxor(a, b * -1)  -- TODO bit
end

-- state management
function initState()
  state.payload_len  = nil
  state.msg_type_num = nil
  state.msg_payload  = nil
end

function updateState(msg_size, payload_len, msg_type, msg_type_num, msg_payload)

  if msg_size ~= nil and msg_type ~= nil and msg_payload ~= nil then
    initState()
    return
  end 

  if msg_size ~= nil and msg_type ~= nil and msg_payload == nil then
    state.payload_len  = payload_len 
    state.msg_type_num = msg_type_num
    state.msg_payload  = nil
    return
  end 
  
  if msg_size ~= nil and msg_type == nil and msg_payload == nil then
    state.payload_len  = payload_len 
    state.msg_type_num = nil
    state.msg_payload  = nil
    return
  end 

  -- TODO error message
  initState()

end

DissectorTable.get("tcp.port"):add(8000,xproto)


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
function processTree(tvb, msg, subtree, len) -- tvb, msg, subtree, len -> subtree
                                             -- [0a 03 74 6c 73 12 08 08 01 12 04 08 07 40 00], Capability, tree_capability, 15
  -- info(string.format("*processTree len (%d)", len))
  local l_pos = 0
  local l_tvb = tvb
  local l_msg = msg
  local l_msg_len = tvb:len()
  local l_subtree = subtree

  while (l_pos < l_msg_len) do
     local l_wire_type, l_tag_no, l_po = getwiretag(l_pos, l_tvb) -- 0a
     l_pos = l_pos + 1

     -- info(string.format("*wire_type(%d), tag_no(%d)", l_wire_type, l_tag_no))
     if l_wire_type == 0 then
       -- info("*l_wire_type == 0")
       local val, acc, po, readsize = getLengthVal(l_pos, l_tvb)
       l_pos = l_pos + readsize
       -- info(string.format("val (%d)", val))
       -- info(l_msg)
       -- info(l_msg[l_tag_no])
       -- info(l_msg[l_tag_no].protofield)
       item = l_subtree:add(l_msg[l_tag_no].protofield, l_tvb(l_pos - readsize , readsize))
       item :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) value (%d) acc (%d)", po, l_wire_type, l_tag_no, val, acc))

     elseif l_wire_type == 2 then
       -- info("*l_wire_type == 2")
       -- info(l_msg[l_tag_no])
       local l_type = l_msg[l_tag_no].type                              -- tag=1 --> l_type=string
       info(string.format("*type(%s)", l_type))
       local le, acc, po, readsize = getLengthVal(l_pos, l_tvb)
       l_pos = l_pos + readsize

       if isTerminal(l_type) then
         -- info("*isTerminal")
         local l_next_tvb = l_tvb(l_pos, acc)
         va = l_tvb(l_pos, acc) : string()
         l_pos = l_pos + acc
         l_subtree
           :add(l_msg[l_tag_no].protofield, l_next_tvb)
           :add (string.format("[(%d)] wiret_type (%d), tag_no (%d) length (%d) acc(%d) value (%s)"
                         , po, l_wire_type, l_tag_no, le, acc, va))
       else 
         -- recursive
         -- info("*recursive")
         local l_next_tvb = l_tvb(l_pos, acc)
         l_pos = l_pos + acc
         -- info(l_msg[l_tag_no])
         -- info(l_msg[l_tag_no].name)
         -- info(l_msg[l_tag_no].type)
         -- info(l_msg[l_tag_no].protofield)
         local l_next_msg = message_table[l_msg[l_tag_no].type]
         local l_next_subtree = l_subtree:add(l_msg[l_tag_no].protofield, l_next_tvb)
         processTree(l_next_tvb, l_next_msg, l_next_subtree, acc) 
       end

     end
  end
end


