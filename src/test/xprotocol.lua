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
  local msg_size = tvb(offset, 4)
  local payload_len = msg_size :le_int() - 1
  offset = offset + 4
  -- type
  local msg_type = tvb(offset, 1)
  local msg_type_num = msg_type :int() 
  offset = offset + 1
  -- payload
  info (string.format("tvb_len=%d, offset=%d, payload_len=%d", tvb:len(), offset, payload_len))
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
  -- info("xproto.dissector, packet_cnt=" .. packet_cnt);

  local subtree = tree:add (xproto, tvb())

  local direction = (pinfo.src_port == p.server_port) and true or false                        -- TODO port should be retrieve from user pref.
  subtree:append_text (direction and " server -> client " or " client -> server ")

  local offset = 0

  -- 1st message
  messages = subtree:add (f.message, tvb(offset,5)) 
  
  offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload = getMessageParts (offset, tvb)
  messages:add (f.size, msg_size) :append_text (string.format(" msg_len (%d) : payload_len (%d)", payload_len+1, payload_len))
  messages:add (f.tipe, msg_type) :append_text (string.format(" (%d)", msg_type_num))
  if msg_payload then messages:add (f.payload, msg_payload) end

  -- 2nd message
  messages = subtree:add (f.message, tvb(offset,5)) 
  
  offset, msg_size, payload_len, msg_type, msg_type_num, msg_payload = getMessageParts (offset, tvb)
  messages:add (f.size, msg_size) :append_text (string.format(" msg_len (%d) : payload_len (%d)", payload_len+1, payload_len))
  messages:add (f.tipe, msg_type) :append_text (string.format(" (%d)", msg_type_num))
  if msg_payload then messages:add (f.payload, msg_payload) end

end

DissectorTable.get("tcp.port"):add(8000,xproto)




