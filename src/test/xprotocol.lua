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
f.size      = ProtoField.bytes  ("XProtocol.size"      , "Size"   )
f.tipe      = ProtoField.bytes  ("XProtocol.type"      , "Type"   )
f.payload   = ProtoField.bytes  ("XProtocol.payload"   , "Payload")

function xproto.dissector (tvb, pinfo, tree) -- testy vertual tvbfer
  pinfo.cols.protocol = "XPROTO"
  packet_cnt = packet_cnt + 1
  -- info("xproto.dissector, packet_cnt=" .. packet_cnt);

  local subtree = tree:add (xproto, tvb())

  local direction = (pinfo.src_port == p.server_port) and true or false                        -- TODO port should be retrieve from user pref.
  subtree:append_text (direction and " server -> client " or " client -> server ")

  -- size
  local msg_size = tvb(0, 4)
  subtree:add (f.size, msg_size)
  -- type
  local msg_type = tvb(4, 1)
  subtree:add (f.tipe, msg_type)
  -- payload


  -- info("msg_size=" .. msg_size) 
end

DissectorTable.get("tcp.port"):add(8000,xproto)
