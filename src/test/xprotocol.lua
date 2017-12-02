local xproto = Proto ("XProtocol", "X Protocol Dissector");

local packet_cnt

function xproto.init () 
  packet_cnt = 0
end

local f = xproto.fields

-- f.direction = ProtoField.bytes  ( "XProtocol.direction" , "Direction" )
f.size      = ProtoField.bytes  ( "XProtocol.size"      , "Size"      )
f.tipe      = ProtoField.bytes  ( "XProtocol.type"      , "Type"      )
f.payload   = ProtoField.bytes  ( "XProtocol.payload"   , "Payload"   )

function xproto.dissector (buf, pkt, tree) -- testy vertual buffer
  pkt.cols.protocol = "XPROTO"
  packet_cnt = packet_cnt + 1
  info("xproto.dissector, packet_cnt=" .. packet_cnt);

  local subtree = tree:add (xproto, buf())


  subtree:append_text (" client -> server " )
  

  -- size
  local msg_size = buf(0, 4)
  subtree:add (f.size, msg_size)
  -- type
  local msg_type = buf(4, 1)
  subtree:add (f.tipe, msg_type)
  -- payload


  info("msg_size=" .. msg_size) 
end

DissectorTable.get("tcp.port"):add(8000,xproto)
