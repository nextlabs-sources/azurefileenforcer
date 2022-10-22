--- https://sharkfestus.wireshark.org/sharkfest.09/DT06_Bjorlykke_Lua%20Scripting%20in%20Wireshark.pdf

----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing the preferences through the
-- GUI or command-line; the Lua-side of that preference handling is at the end of this script file
local default_settings = {
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 6666, -- default TCP port number for FPM
    max_msg_len  = 4096, -- max length of FPM message
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            -- Writes a log message with informational severity to the Lua console and stdout
            info(table.concat({"Lua|", ...}))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()

-- Define our protocol
nxl_fileinfo = Proto("nxl_fileinfo", "NXL FileInfo Proto")

----------------------------------------
---- a table of all of our Protocol's fields
-- * Integer types: ProtoField.{type} (abbr, [name], [desc], [base], [valuestring], [mask])
--    uint8, uint16, uint24, uint32, uint64, framenum
-- * Other types: ProtoField.{type} (abbr, [name], [desc])
--    float, double, string, stringz, bytes, bool, ipv4, ipv6, ether, oid, guid
-- See https://cse.sc.edu/~pokeefe/tutorials/wireshark/wsluarm_modules.html#lua_fn_ProtoField_uint32_abbr___name____base____valuestring____mask____desc__
--local hdr_fields =
--{
--    version   = ProtoField.uint8 ("fpm.version", "Version", base.DEC),
--    msg_type  = ProtoField.uint8 ("fpm.type", "Type", base.DEC, msgtype_valstr),
--    msg_len   = ProtoField.uint16("fpm.length", "Length", base.DEC),
--}
---- register the ProtoFields
--nxl_fileinfo.fields = hdr_fields

local fs = nxl_fileinfo.fields

fs.protocol = ProtoField.string ("nxl_fileinfo.protocol", "Protocol")
fs.size = ProtoField.uint32 ("nxl_fileinfo.size", "Size", base.DEC) -- info (payload) size
fs.info = ProtoField.new ("Info", "nxl_fileinfo.info", ftypes.STRING)

-- local ttl_field = Field.new("ip.ttl") -- local ttl = ttl_field() -- now "ttl" contains a FieldInfo instance

local PROTOCOL = "NXFILEINFOHEADER"
local PROTOCOL_SIZE = #PROTOCOL

--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "nxl_fileinfo.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
-- See https://wiki.wireshark.org/LuaAPI/Tvb#Tvb, https://wiki.wireshark.org/LuaAPI/TreeItem
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html
function nxl_fileinfo.dissector( tvbuf, pktinfo, tree )
    dprint("nxl_fileinfo.dissector called, port: " .. pktinfo.src_port .. ">" .. pktinfo.dst_port) -- .. pktinfo.dst .. ":"
	
    -- ignore packets less than 4 bytes long
    if tvbuf:len() < PROTOCOL_SIZE + 4 then return end

    -- TODO check protocol
    local protocol_buf = tvbuf(0, PROTOCOL_SIZE)
    local size_buf = tvbuf(PROTOCOL_SIZE, 4)
    local size = size_buf:le_uint() -- info (payload) size
    if size > default_settings.max_msg_len then
        dprint("NXL FileInfo message length is too long: ", size) -- too many bytes, invalid message
        -- If the result is 0, then it means we hit an error of some kind, so return 0. Returning 0
        -- tells Wireshark this packet is not for us, and it will try heuristic dissectors or the
        -- plain "data" one, which is what should happen in this case.
        return 0
    elseif tvbuf:len() < size + PROTOCOL_SIZE + 4 then return -- wait until more data
    end
	
	-- tree:append_text("Columns (for debug purposes only): " .. tostring(pktinfo.cols.info))
	
	-- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("NxlFileInfo")
	-- set brief information for each some GUI packet row, in the INFO column cell
    -- this line of code uses a Lua trick for doing something similar to the C/C++ 'test ? true : false' shorthand
    -- pktinfo.cols.info:prepend(pktinfo.cols.direction and "true " or "false ")

    local subtree = tree:add( nxl_fileinfo, tvbuf(0, size))
	-- tree:append_text("direction=" .. type(pktinfo.cols.direction)) -- packet direction tostring()

    local info_buf = tvbuf(PROTOCOL_SIZE + 4, size)

    subtree:add( protocol_buf, "Protocol: "  .. protocol_buf:string() )
    subtree:add( size_buf, "Size: "     .. size ) -- subtree:add_le
    -- subtree:add( fs.info, "Info: " .. info_buf )
	
    json_dissector = Dissector.get("json")
    ---- skip over the header in front of the encapsulated nxl_fileinfo packet
    json_dissector:call( info_buf:tvb(), pktinfo, subtree )

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)

    -- tell wireshark how much of tvbuff we dissected
    return size
end

--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the DissectorTable:add()
    -- one adds ours before any existing ones, but leaves the other ones alone, which is better
    DissectorTable.get("tcp.port"):add(default_settings.port, nxl_fileinfo)
end
-- call it now, because we're enabled by default
enableDissector()
-- register nxl_fileinfo as a postdissector
-- register_postdissector(nxl_fileinfo)

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, nxl_fileinfo)
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = { { 1,  "Disabled", debug_level.DISABLED }, { 2,  "Level 1",  debug_level.LEVEL_1  }, { 3,  "Level 2",  debug_level.LEVEL_2  } }

----------------------------------------
-- register our preferences
nxl_fileinfo.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled, "Whether the FPM dissector is enabled or not")
nxl_fileinfo.prefs.debug       = Pref.enum("Debug", default_settings.debug_level, "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function nxl_fileinfo.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = nxl_fileinfo.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= nxl_fileinfo.prefs.enabled then
        default_settings.enabled = nxl_fileinfo.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")

-- https://blog.keyidentity.com/2017/06/20/pwnadventure3-building-a-wireshark-parser/
-- https://github.com/Foxmole/PwnAdventure3/blob/master/pwn3.lua