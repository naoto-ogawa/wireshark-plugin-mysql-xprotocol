local xproto = Proto ("XProtocol", "X Protocol Dissector");

local packet_cnt

function xproto.init () 
  packet_cnt = 0
end

-- Preferences
local p = xproto.prefs

p.server_port = Pref.uint ("server port", 8000, "server port number") -- TODO 33060 should be default


-- Fields
local f = xproto.fields

-- f.direction = ProtoField.bytes  ( "XProtocol.direction" , "Direction" )
f.message   = ProtoField.bytes  ("XProtocol.message"   , "Message" )
f.size      = ProtoField.bytes  ("XProtocol.size"      , "Size"    )
f.tipe      = ProtoField.bytes  ("XProtocol.type"      , "Type"    )
f.payload   = ProtoField.bytes  ("XProtocol.payload"   , "Payload" )

function getMessageParts (offset, tvb)
  -- size
  local msg_size
  local payload_len
  if offset + 4 <= tvb:len() then
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
  if offset + 1 <= tvb:len() then
    msg_type     = tvb(offset, 1)
    msg_type_num = msg_type :int() 
    offset = offset + 1
  else
    msg_type     = nil 
    msg_type_num = nil 
  end
  -- payload
  local msg_payload = (offset + payload_len <= tvb:len()) and tvb(offset, payload_len) or nil
  offset = offset + payload_len
  return offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload
end

-- 0123456789  ---- len = 10
-- ++++        0 4 
--     +       4 1
--      +++++  5 5

function xproto.dissector (tvb, pinfo, tree) -- testy vertual tvbfer
  pinfo.cols.protocol = "XPROTO"
  packet_cnt = packet_cnt + 1

  local subtree = tree:add (xproto, tvb())

  local direction = (pinfo.src_port == p.server_port) and true or false
  subtree:append_text (direction and " server -> client " or " client -> server ")

  local offset = 0

  while offset < tvb:len() do
    messages = subtree:add (f.message, tvb(offset,5)) 
    offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload = getMessageParts (offset, tvb)
    messages:add (f.size, msg_size) :append_text (string.format(" msg_len (%d) : payload_len (%d)", payload_len+1, payload_len))
    messages:add (f.tipe, msg_type) :append_text (string.format(" (%d)", msg_type_num))
    if msg_payload then messages:add (f.payload, msg_payload) end
  end

end

DissectorTable.get("tcp.port"):add(8000,xproto)




