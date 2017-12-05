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

f.message   = ProtoField.bytes  ("XProtocol.message"   , "Message" )
f.size      = ProtoField.bytes  ("XProtocol.size"      , "Size"    )
f.tipe      = ProtoField.bytes  ("XProtocol.type"      , "Type"    )
f.payload   = ProtoField.bytes  ("XProtocol.payload"   , "Payload" )

-- state between packets -- TODO not good state management, we need to consider each item is divided between packet.
state = {
    payload_len  = nil
  , msg_type_num = nil
  , msg_payload  = nil
}

--
clientmessagetype = {
   [1]  = "CON_CAPABILITIES_GET"
  ,[2]  = "CON_CAPABILITIES_SET"
  ,[3]  = "CON_CLOSE"
  ,[4]  = "SESS_AUTHENTICATE_START"
  ,[5]  = "SESS_AUTHENTICATE_CONTINUE"
  ,[6]  = "SESS_RESET"
  ,[7]  = "SESS_CLOSE"
  ,[12] = "SQL_STMT_EXECUTE"
  ,[17] = "CRUD_FIND"
  ,[18] = "CRUD_INSERT"
  ,[19] = "CRUD_UPDATE"
  ,[20] = "CRUD_DELETE"
  ,[24] = "EXPECT_OPEN"
  ,[25] = "EXPECT_CLOSE"
  ,[30] = "CRUD_CREATE_VIEW"
  ,[31] = "CRUD_MODIFY_VIEW"
  ,[32] = "CRUD_DROP_VIEW"
}
--
servermessagetype = {
   [0]  = "OK"
  ,[1]  = "ERROR"
  ,[2]  = "CONN_CAPABILITIES"
  ,[3]  = "SESS_AUTHENTICATE_CONTINUE"
  ,[4]  = "SESS_AUTHENTICATE_OK"
  ,[11] = "NOTICE"
  ,[12] = "RESULTSET_COLUMN_META_DATA"
  ,[13] = "RESULTSET_ROW"
  ,[14] = "RESULTSET_FETCH_DONE"
  ,[15] = "RESULTSET_FETCH_SUSPENDED"
  ,[16] = "RESULTSET_FETCH_DONE_MORE_RESULTSETS"
  ,[17] = "SQL_STMT_EXECUTE_OK"
  ,[18] = "RESULTSET_FETCH_DONE_MORE_OUT_PARAMS"
}



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

-- 0123456789  ---- len = 10
-- ++++        0 4 
--     +       4 1
--      +++++  5 5

function xproto.dissector (tvb, pinfo, tree) -- tvb = testy vertual tvbfer
  pinfo.cols.protocol = "XPROTO"
  packet_cnt = packet_cnt + 1

  local subtree = tree:add (xproto, tvb())

  local direction = (pinfo.src_port == p.server_port) and true or false
  subtree:append_text (direction and " server -> client " or " client -> server ")
  -- info (direction and " server -> client " or " client -> server ")

  local offset = 0
  local msg_size, payload_len, msg_type, msg_type_num, msg_payload

  while offset < tvb:len() do
    messages = subtree:add (f.message, tvb(offset,5)) -- first 5 bytes (usually size and type) 
    offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload = getMessageParts (offset, tvb)
    -- info (string.format("**payload_len=%d, msg_type_num=%d, msg_payload=%s", payload_len, msg_type_num, msg_payload))
    if msg_size then
      messages:add (f.size, msg_size) :append_text (string.format(" msg_len (%d) : payload_len (%d)", payload_len+1, payload_len))
    end
    if msg_type then
      messages 
        :add (f.tipe, msg_type) 
        :append_text (string.format(" (%d) ", msg_type_num))
        :append_text (tostring(direction and servermessagetype[msg_type_num] or clientmessagetype[msg_type_num]))
    end
    if msg_payload then 
      messages:add (f.payload, msg_payload) 
    end
    updateState(msg_size, payload_len, msg_type, msg_type_num, msg_payload)
  end
end

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




