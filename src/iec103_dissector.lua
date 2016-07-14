-- IEC 103 protocol analyzer plugin for Wireshark

--Type id description
iec103_typeid_table = {
[1 ] = "Time-tagged message",
[2 ] = "Time-tagged message with relative time",
[3 ] = "Measurands I",
[4 ] = "Time-tagged measurands with relative time",
[5 ] = "Identification",
[6 ] = "Time synchronization",
[7 ] = "General interrogation",
[8 ] = "General interrogation termination",
[9 ] = "Measurands II",
[10] = "Generic data",
[11] = "Generic identification",
[20] = "General command",
[21] = "Generic command",
[23] = "List of recorded disturbances",
[24] = "Order for disturbance data transmission",
[25] = "Acknowledgement for disturbance data transmission",
[26] = "Ready for transmission of disturbance data",
[27] = "Ready for transmission of a channel",
[28] = "Ready for transmission of tags",
[29] = "Transmission of tags",
[30] = "Transmission of disturbance values",
[31] = "End of transmission",
[40] = "Positive acknowledgement of generic write command",
[41] = "Negative acknowledgement of generic write command",
[42] = "Valid data response to generic read command",
[43] = "Invalid data response to generic read command",
[44] = "Generic write confirmation",
}

--Type id description
iec103_kod_table = {
[0]  = "NO KOD SPECIFIED",
[1]  = "ACTUAL VALUE",
[2]  = "DEFAULT VALUE",
[3]  = "RANGE (minimum value, maximum value and step size)",
[4]  = "(reserved)",
[5]  = "PRECISION (n, m)",
[6]  = "FACTOR",
[7]  = "% REFERENCE",
[8]  = "ENUMERATION",
[9]  = "DIMENSION",
[10] = "DESCRIPTION",
[11] = "(reserved)",
[12] = "PASSWORD ENTRY",
[13] = "IS READ ONLY",
[14] = "IS WRITE ONLY",
[15] = "(reserved)",
[16] = "(reserved)",
[17] = "(reserved)",
[18] = "(reserved)",
[19] = "CORRESPONDING FUNCTION TYPE AND INFORMATION NUMBER",
[20] = "CORRESPONDING EVENT",
[21] = "ENUMERATED TEXT ARRAY",
[22] = "ENUMERATED VALUE ARRAY",
[23] = "RELATED ENTRIES",
}

--Cause of transfer
iec103_cot_table = {
[1 ] = "Spontaneous",
[2 ] = "Cyclic",
[3 ] = "Reset frame count bit (FCB)",
[4 ] = "Reset communication unit (CU)",
[5 ] = "Start / restart",
[6 ] = "Power on",
[7 ] = "Test mode",
[8 ] = "Time synchronization",
[9 ] = "General interrogation",
[10] = "Termination of general interrogation",
[11] = "Local operation",
[12] = "Remote operation",
[20] = "Positive acknowledgement of command",
[21] = "Negative acknowledgement of command",
[31] = "Transmission of disturbance data",
[40] = "Positive acknowledgement of generic write command",
[41] = "Negative acknowledgement of generic write command",
[42] = "Valid data response to generic read command",
[43] = "Invalid data response to generic read command",
[44] = "Generic write confirmation",
}

local iec103_func_type_table = {
[128] = "t(z) distance protection ",
[160] = "I>>  overcurrent protection ",
[176] = "DIT  transformer differential protection ",
[192] = "DIL  line differential protection ",
[254] = "GEN  generic function type ",
[255] = "GLB  global function type ",
}

local iec103_data_type_table = {
[0]  = "No data",
[1]  = "OS8ASCII,OS8[1..8][ASCII 8-bit-code>",
[2]  = "PACKEDBITSTRING := BS1",
[3]  = "UI",
[4]  = "I",
[5]  = "UF",
[6]  = "F",
[7]  = "R32.23 := Short real IEEE 754",
[8]  = "R64.53 := Real IEEE 754",
[9]  = "DOUBLE POINT INFORMATION (see 7.2.6.5)",
[10] = "SINGLE POINT INFORMATION",
[11] = "DOUBLE POINT INFORMATION WITH TRANSIENT AND ERROR,UI2[1..2] [0..3>",
[12] = "MEASURAND WITH QUALITY DESCRIPTOR (see 7.2.6.8)",
[13] = "Reserved",
[14] = "BINARY TIME (see 7.2.6.29)",
[15] = "GENERIC IDENTIFICATION NUMBER (see 7.2.6.31)",
[16] = "RELATIVE TIME (see 7.2.6.15)",
[17] = "FUNCTION TYPE AND INFORMATION NUMBER,CP16 {Type, INF}",
[18] = "TIME TAGGED MESSAGE,CP48 {DPI, RES, TIME, SIN}",
[19] = "TIME TAGGED MESSAGE WITH RELATIVE TIME,CP80 {DPI, RES, RET, FAN, TIME, SIN}",
[20] = "TIME TAGGED MEASURAND WITH RELATIVE TIME,CP96 {VAL, RET, FAN, TIME}",
[21] = "EXTERNAL TEXT NUMBER := UIi",
[22] = "GENERIC REPLY CODE (see 7.2.6.36)",
[23] = "DATA STRUCTURE,CPii{(GDD, GID)} (see 7.2.6.32 and 7.2.6.33)",
[24] = "INDEX",
}

iec103_prm1_func_table = {
[0]   = "Reset of Remote link. Frame type: SEND/CONFIRM expected",
[1]   = "Reset of user process. Frame type: SEND/CONFIRM expected",
[2]   = "Reserved. Frame type: SEND/CONFIRM expected",
[3]   = "User data. Frame type: SEND/CONFIRM expected",
[4]   = "User data. Frame type: SEND/NO REPLY expected",
[5]   = "Reserved",
[6]   = "Reserved for special use by agreement",
[7]   = "Reserved for special use by agreement",
[8]   = "Expected response specifies access demand. Frame type: REQUEST for access demand",
[9]   = "Request status of link. Frame type: REQUEST/RESPOND expected",
[10]  = "Request user data class 1. Frame type: REQUEST/RESPOND expected",
[11]  = "Request user data class 2. Frame type: REQUEST/RESPOND expected",
[12]  = "Reserved",
[13]  = "Reserved",
[14]  = "Reserved for special use by agreement",
[15]  = "Reserved for special use by agreement",
}

iec103_prm0_func_table = {
[0]   = "ACK:positive acknowledgement. Frame type: CONFIRM",
[1]   = "NACK:message not accepted, link busy. Frame type: CONFIRM",
[2]   = "Reserved",
[3]   = "Reserved",
[4]   = "Reserved",
[5]   = "Reserved",
[6]   = "Reserved for special use by agreement",
[7]   = "Reserved for special use by agreement",
[8]   = "User data. Frame type: RESPOND",
[9]   = "NACK:requested data not available. Frame type: RESPOND",
[10]  = "Reserved",
[11]  = "Status of link or access demand. Frame type: RESPOND",
[12]  = "Reserved",
[13]  = "Reserved for special use by agreement",
[14]  = "Link service not functioning",
[15]  = "Link service not implemented",

}

iec103_dayofweek_table = {
[0]  = "Mon",
[1]  = "Tue",
[2]  = "Wed",
[3]  = "Thu",
[4]  = "Fri",
[5]  = "Sat",
[6]  = "Sun",

}

iec103_valid_table = {
[0 ] = "Valid",
[1 ] = "Invalid"
}

iec103_spi_str_table = {
[0] = "OFF",
[1] = "ON"
}

iec103_dpi_str_table = {
[0] = "Indeterminate/intermediate",
[1] = "OFF",
[2] = "ON",
[3] = "Indeterminate"
}
-- declare our protocol
iec103 = Proto("iec103", "IEC 60870-5-103")

local msg_start = ProtoField.uint8("iec103.Start_Byte","Start",base.HEX)
local msg_length = ProtoField.uint8("iec103.Msg_Length","Length",base.DEC)
local msg_length_rep = ProtoField.uint8("iec103.Msg_Length_Rep","Length_Repeat",base.DEC)
local msg_start_rep = ProtoField.uint8("iec103.Start_Byte_Rep","Start_Repeat",base.HEX)
local msg_ctrl = ProtoField.uint8("iec103.Control_Field","Control_Field",base.HEX)
local msg_ctrl_prm = ProtoField.string("iec103.PRM","PRM")
local msg_ctrl_fcb_acd = ProtoField.string("iec103.FCB_ACD","FCB/ACD")
local msg_ctrl_fcv_dfc = ProtoField.string("iec103.PRM","FCV/DFC")
local msg_ctrl_func = ProtoField.string("iec103.FUNCTION","Function")

local msg_link_addr = ProtoField.uint16("iec103.Link_Addr","Link_Addr",base.DEC)

--local msg_ASDU = ProtoField.uint8("iec103.ASDU","ASDU",base.HEX)
local msg_ASDU = ProtoField.string("iec103.ASDU","ASDU")

local msg_typeid = ProtoField.uint8("iec103.Type_id","Type_id",base.DEC)
local msg_vsq = ProtoField.uint8("iec103.VSQ","Variable_Structure_Qualifier",base.HEX)
local msg_vsq_sq = ProtoField.string("iec103.VSQ_SQ","SQ = ")
local msg_vsq_obj_num = ProtoField.string("iec103.VSQ_OBJ_NUM","Object number = ")

local msg_cot = ProtoField.uint8("iec103.Cause_of_Trans","Cause of Trans",base.DEC)
local msg_comm_addr = ProtoField.uint8("iec103.Common_Addr","Common_address",base.DEC)
local msg_obj_addr = ProtoField.uint8("iec103.Obj_Addr","Obj_address",base.DEC)
local msg_obj = ProtoField.string("iec103.Objects","Objects")
local msg_obj_single = ProtoField.string("iec103.Object_Single","Object")
local msg_obj_value = ProtoField.string("iec103.Object_Value","Value")

local msg_func_type = ProtoField.string("iec103.Function_Type","Func_Type")
local msg_info_num = ProtoField.string("iec103.Info_Num","Info_Num")

local msg_dpi = ProtoField.string("iec103.DPI","DPI")
local msg_bin_time = ProtoField.string("iec103.BIN_TIME","BIN_Time")
local msg_sin = ProtoField.string("iec103.SIN","Supplementary information")

local msg_ret = ProtoField.string("iec103.Relative_time","Relative time")
local msg_fan = ProtoField.string("iec103.Fault_number","Fault number")

local msg_mea = ProtoField.string("iec103.Measurands_I","Measurands I")
local msg_scl = ProtoField.string("iec103.Short_Circuit_Location","Short Circuit Location")

local msg_col = ProtoField.string("iec103.Compatibility_level","Compatibility level")
local msg_asc = ProtoField.string("iec103.Char","Char")
local msg_scn = ProtoField.string("iec103.Scan_number","Scan number")

local msg_dset = ProtoField.string("iec103.Dataset","Data Set")
local msg_rii = ProtoField.string("iec103.RII","Return information identifier")
local msg_ngd = ProtoField.string("iec103.NGD","Number of generic data sets")
local msg_gin = ProtoField.string("iec103.GIN","Generic identification number")
local msg_gdd = ProtoField.string("iec103.GDD","Generic data description")
local msg_gdd_datatype = ProtoField.string("iec103.GDD_Datatype","Data Type")
local msg_gdd_datasize = ProtoField.string("iec103.GDD_Datasize","Data Size")
local msg_gdd_number = ProtoField.string("iec103.GDD_number","Number")
local msg_gdd_continue = ProtoField.string("iec103.GDD_continue","Continue Data")

local msg_gid = ProtoField.string("iec103.GID","Generic identification data")
local msg_kod = ProtoField.string("iec103.KOD","Kind of description")


local msg_gid_data = ProtoField.string("iec103.GID_DATA","Data")

local msg_cp56 = ProtoField.string("iec103.CP56Time2a","CP56Time2a")

local msg_checksum = ProtoField.uint8("iec103.Check_Sum","Check_Sum",base.HEX)
local msg_end = ProtoField.uint8("iec103.End_Byte","End",base.HEX)

local msg_debug = ProtoField.string("iec103.DebugStr","DebugStr")

iec103.fields = {msg_start,msg_length,msg_length_rep,msg_start_rep,msg_ctrl, msg_link_addr, msg_ASDU, msg_typeid, msg_vsq, msg_checksum, msg_end,msg_vsq_sq,msg_vsq_obj_num, msg_cot , msg_comm_addr, msg_func_type,msg_info_num, msg_dpi, msg_bin_time,msg_sin, msg_ret, msg_fan ,msg_rii, msg_ngd, msg_gin, msg_gdd, msg_gid, msg_gid_data, msg_kod, msg_obj_addr, msg_obj, msg_obj_single, msg_obj_value, msg_debug,msg_mea,msg_scl,msg_asc,msg_col,msg_scn,msg_dset,msg_cp56, msg_gdd_datatype,msg_gdd_datasize,msg_gdd_number,msg_gdd_continue,msg_ctrl_prm,msg_ctrl_fcb_acd, msg_ctrl_fcv_dfc,msg_ctrl_func }

--protocol parameters in Wiresh preference
local ZEROBYTE   = 0
local ONEBYTE    = 1
local TWOBYTE    = 2
local THREEBYTE  = 3
 
local table_012 = {
        { 0, "Zero Byte"        , ZEROBYTE },
		{ 1, "One Byte"         , ONEBYTE },
        { 2, "Two Bytes"        , TWOBYTE },
}

-- Create enum preference that shows as radio button under
-- iec103 Protocol's preferences
-- Link address width
iec103.prefs.linkaddrbytes = Pref.enum(
        "Link address width:",                 				-- label
        ONEBYTE,                    						-- default value
        "Zero, One or two bytes for link address field",  	-- description
        table_012,                     						-- enum table
        true                           						-- show as radio button
)

local funccount = 0

function Get_gid_data(t_gid,buffer, start_pos, datatype,datasize)
	local valstr = ""
	if datatype == 1 then
		local val = buffer(start_pos,1):uint()
		valstr = tostring(val)
	elseif datatype == 2 then
		valstr = buffer(start_pos,datasize):tostring()
	elseif datatype == 3 then
		local val = buffer(start_pos,datasize):le_uint()
		valstr = tostring(val)
	elseif datatype == 4 then
		local val = buffer(start_pos,datasize):le_int()
		valstr = tostring(val)
	elseif datatype == 5 then
		local val = buffer(start_pos,1):uint()
		local val_2 = val/256.0
		valstr = string.format("%.6f",val_2)
	elseif datatype == 18 then
		local dpi = buffer(start_pos,1):bitfield(6,2)
		valstr = "DPI:"..iec103_dpi_str_table[dpi]
	elseif datatype == 19 then
		local dpi = buffer(start_pos,1):bitfield(6,2)
		valstr = "DPI:"..iec103_dpi_str_table[dpi]
	end
	
	return valstr
end

function Get_element(t_asdu, msgtypeid, func_type, info_num, buffer,start_pos)

	if msgtypeid:uint() == 1 then
		t_asdu:add(msg_dpi, buffer(start_pos, 1), iec103_dpi_str_table[buffer(start_pos,1):uint()])
		
		start_pos = start_pos + 1
		
		local tmpstart = start_pos
		local tmsec = (buffer(start_pos,2):le_uint())/1000.0
		local msec = string.format("%.3f",tmsec)
		start_pos = start_pos + 2
		
		local validstr = "Invalid"
		if buffer(start_pos,1):bitfield(0,1) == 0 then
			validstr = "Valid"
		else
			validstr = "Invalid"
		end
		
		local minute = tostring(buffer(start_pos,1):bitfield(2,6))
		start_pos = start_pos + 1
		
		local summertime = ""
		
		if (buffer(start_pos,1):bitfield(0,1) == 1) then
			summertime = "Summer Time"
		else
			summertime = "Standard Time"
		end
		
		local hour = tostring(buffer(start_pos,1):bitfield(3,5))
		
		t_asdu:add(msg_bin_time, buffer(tmpstart, 4), hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr)
		
		start_pos = start_pos + 1
		t_asdu:add(msg_sin,buffer(start_pos, 1),buffer(start_pos, 1):uint())
		
	elseif msgtypeid:uint() == 2 then
		t_asdu:add(msg_dpi, buffer(start_pos, 1), iec103_dpi_str_table[buffer(start_pos,1):uint()])
		start_pos = start_pos + 1
		
		t_asdu:add(msg_ret,buffer(start_pos, 2),tostring(buffer(start_pos, 2):le_uint()).."ms")
		start_pos = start_pos + 2
		
		t_asdu:add(msg_fan,buffer(start_pos, 2),buffer(start_pos, 2):le_uint())
		start_pos = start_pos + 2
		
		local tmpstart = start_pos
		local tmsec = (buffer(start_pos,2):le_uint())/1000.0
		local msec = string.format("%.3f",tmsec)
		start_pos = start_pos + 2
		
		local validstr = "Invalid"
		if buffer(start_pos,1):bitfield(0,1) == 0 then
			validstr = "Valid"
		else
			validstr = "Invalid"
		end
		
		local minute = tostring(buffer(start_pos,1):bitfield(2,6))
		start_pos = start_pos + 1
		
		local summertime = ""
		
		if (buffer(start_pos,1):bitfield(0,1) == 1) then
			summertime = "Summer Time"
		else
			summertime = "Standard Time"
		end
		
		local hour = tostring(buffer(start_pos,1):bitfield(3,5))
		
		t_asdu:add(msg_bin_time, buffer(tmpstart, 4), hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr)
		
		start_pos = start_pos + 1
		
		--t_asdu:add(msg_bin_time, buffer(start_pos+5, 4), buffer(start_pos+5, 4):uint())
		t_asdu:add(msg_sin,buffer(start_pos, 1),buffer(start_pos, 1):uint())
	elseif msgtypeid:uint() == 3 then
		t_asdu:add(msg_mea,buffer(start_pos,2),"current L2 = "..buffer(start_pos,2):tostring())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_mea,buffer(start_pos,2),"voltage L1-L2 = "..buffer(start_pos,2):tostring())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_mea,buffer(start_pos,2),"active power = "..buffer(start_pos,2):tostring())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_mea,buffer(start_pos,2),"reactive power Q = "..buffer(start_pos,2):tostring())
		
	elseif msgtypeid:uint() == 4 then
		t_asdu:add(msg_scl,buffer(start_pos,4),tostring(buffer(start_pos,4):float()))
		
		start_pos = start_pos + 4
		t_asdu:add(msg_ret,buffer(start_pos, 2),buffer(start_pos, 2):uint())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_fan,buffer(start_pos, 2),buffer(start_pos, 2):uint())
		
		start_pos = start_pos + 2
		t_asdu:add(msg_bin_time, buffer(start_pos, 4), buffer(start_pos, 4):uint())
		
	elseif msgtypeid:uint() == 5 then
		t_asdu:add(msg_col,buffer(start_pos,1),tostring(buffer(start_pos,1):uint()))
		
		start_pos = start_pos + 1
		
		local char1 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char2 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char3 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char4 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char5 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char6 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char7 = string.char(buffer(start_pos,1):uint())
		start_pos = start_pos + 1
		local char8 = string.char(buffer(start_pos,1):uint())
		
		t_asdu:add(msg_asc,buffer(start_pos,1),": "..char1..char2..char3..char4..char5..char6..char7..char8)
		
		--[[
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"2 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"3 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"4 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"5 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"6 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"7 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"8 : "..tostring(buffer(start_pos,1)))
		--]]
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"ext 1 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"ext 2 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"ext 3 : "..tostring(buffer(start_pos,1)))
		
		start_pos = start_pos + 1
		t_asdu:add(msg_asc,buffer(start_pos,1),"ext 4 : "..tostring(buffer(start_pos,1)))
		
		
	elseif msgtypeid:uint() == 6 then
	
		local tmpstart = start_pos
		local tmsec = (buffer(start_pos,2):le_uint())/1000.0
		local msec = string.format("%.3f",tmsec)
		start_pos = start_pos + 2
		
		local validstr = "Invalid"
		if buffer(start_pos,1):bitfield(0,1) == 0 then
			validstr = "Valid"
		else
			validstr = "Invalid"
		end
		
		local minute = tostring(buffer(start_pos,1):bitfield(2,6))
		start_pos = start_pos + 1
		
		local summertime = ""
		
		if (buffer(start_pos,1):bitfield(0,1) == 1) then
			summertime = "Summer Time"
		else
			summertime = "Standard Time"
		end
		
		local hour = tostring(buffer(start_pos,1):bitfield(3,5))
		start_pos = start_pos + 1
		
		local dayofweek = iec103_dayofweek_table[buffer(start_pos,1):bitfield(0,3)]
		local dayofmonth = tostring(buffer(start_pos,1):bitfield(3,5))
		start_pos = start_pos + 1
		
		local month = tostring(buffer(start_pos,1):bitfield(4,4))
		start_pos = start_pos + 1
		
		local year = tostring(2000+buffer(start_pos,1):bitfield(1,7))
		start_pos = start_pos + 1
		
		t_asdu:add(msg_cp56,buffer(tmpstart,7),year.."/"..month.."/"..dayofmonth.."(Y/M/D) "..dayofweek.." "..hour..":"..minute..":"..msec.." "..summertime.." -- "..validstr)
		
	elseif msgtypeid:uint() == 7 then
		t_asdu:add(msg_scn,buffer(start_pos,1), buffer(start_pos,1):uint())
		
	elseif msgtypeid:uint() == 8 then
	
	elseif msgtypeid:uint() == 9 then
	
	elseif msgtypeid:uint() == 10 then
		t_asdu:add(msg_rii, buffer(start_pos, 1), buffer(start_pos, 1):uint())
		
		start_pos = start_pos + 1
		local dNo = buffer(start_pos, 1):bitfield(2,6)
		local dcount = buffer(start_pos, 1):bitfield(1,1)
		local dcont = buffer(start_pos, 1):bitfield(0,1)
		
		t_asdu:add(msg_ngd, buffer(start_pos, 1), tostring(dNo)..",further ASDU with same RII:"..tostring(dcont))
		
		start_pos = start_pos + 1
		
		local maglen = buffer(1,1):uint()
		local dsetcnt = 1
		while start_pos <= maglen do
			local t_dset = t_asdu:add(msg_dset,buffer(start_pos, 2),dsetcnt)
			dsetcnt = dsetcnt + 1
			
			local group_str = tostring(buffer(start_pos, 1):uint())
			local entry_str = tostring(buffer(start_pos+1, 1):uint())
			t_dset:add(msg_gin, buffer(start_pos, 2), "Group:"..group_str..",Entry:"..entry_str)
			
			start_pos = start_pos + 2
			t_dset:add(msg_kod, buffer(start_pos, 1), iec103_kod_table[buffer(start_pos, 1):uint()])
			
			start_pos = start_pos + 1
			local datatype = buffer(start_pos, 1):uint()
			local datasize = buffer(start_pos+1, 1):uint()
			local number = buffer(start_pos+2, 1):bitfield(1,7)
			local cont_d = buffer(start_pos+2, 1):bitfield(0,1)
			
			local datatype_str = tostring(datatype)
			local datasize_str = tostring(datasize)
			local number_str = tostring(number)
			local contdata_str = tostring(cont_d)
			
			local t_gdd = t_dset:add(msg_gdd, buffer(start_pos, 3), iec103_data_type_table[datatype])
			
			t_gdd:add(msg_gdd_datatype,buffer(start_pos,1),datatype_str.."--"..iec103_data_type_table[datatype])
			t_gdd:add(msg_gdd_datasize,buffer(start_pos+1,1),datasize_str)
			t_gdd:add(msg_gdd_number,buffer(start_pos+2,1),number_str)
			t_gdd:add(msg_gdd_continue,buffer(start_pos+2,1),contdata_str)
			
			start_pos = start_pos + 3
			t_gid = t_dset:add(msg_gid, buffer(start_pos, datasize*number),">>>")
			
			local startdatapos = start_pos
			
			local cnt = 0
			
			for cnt = 1, number, 1 do
				local gid_data_str = Get_gid_data(t_gid, buffer, start_pos, datatype,datasize)
				t_gid:add(msg_gid_data,buffer(startdatapos, datasize), tostring(cnt).."--> "..gid_data_str)
				startdatapos = startdatapos + datasize
			end
			
			start_pos = startdatapos
		end
		
	end
end


-- create a function to dissect it
function iec103.dissector(buffer,pinfo,tree)
   
	pinfo.cols.protocol = iec103.name
	
	local msgstartbyte = buffer(0,1):uint()
	
	local iec103_link_addr_bytes = iec103.prefs.linkaddrbytes
	local iec103_comm_addr_bytes = 1
	local iec103_cot_bytes = 1
	
	if msgstartbyte == 16 then
		local t0 = tree:add(iec103,buffer(), "IEC 60870-5-103 Fixed Length Message")
		t0:add(msg_start, buffer(0,1))
		
		local prm = buffer(1,1):bitfield(1,1)
		local fcb_acd  = buffer(1,1):bitfield(2,1)
		local fcv_dfc  = buffer(1,1):bitfield(3,1)
		local func  = buffer(1,1):bitfield(4,4)
		
		local t1 = t0:add(msg_ctrl, buffer(1,1))
		
		t1:add(msg_ctrl_prm,buffer(1,1),tostring(prm))
		
		if prm == 1 then
			t1:add(msg_ctrl_fcb_acd,buffer(1,1)," FCB = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(1,1)," FCV = "..tostring(fcv_dfc))
			if ((fcv_dfc == 0) and (func == 0 or func == 1 or func == 4 or func == 8 or func == 9)) or 
			   ((fcv_dfc == 1) and (func == 3 or func == 10 or func == 11)) or
			   (func == 2 or (func > 5 and func < 7) or (func > 12 and func <15)) then
				t1:add(msg_ctrl_fcb_acd,buffer(1,1),iec103_prm1_func_table[func])
			end
		else
			t1:add(msg_ctrl_fcb_acd,buffer(1,1)," ACD = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(1,1)," DFC = "..tostring(fcv_dfc))
			
			t1:add(msg_ctrl_fcb_acd,buffer(1,1),iec103_prm0_func_table[func])
		end
		
		t0:add_le(msg_link_addr,buffer(2,iec103_link_addr_bytes))
				
		t0:add(msg_checksum, buffer(2 + iec103_link_addr_bytes,1))
		t0:add(msg_end, buffer(3 + iec103_link_addr_bytes,1))
		
		t0:add(msg_debug,iec103_link_addr_bytes)
		
	elseif msgstartbyte == 104 then
		local t0 = tree:add(iec103,buffer(), "IEC 60870-5-103 Variable Length Message")
		
		t0:add(msg_start, buffer(0,1))
		t0:add(msg_length,buffer(1,1))
		t0:add(msg_length_rep,buffer(2,1))
		t0:add(msg_start_rep, buffer(3,1))
		--t0:add(msg_ctrl, buffer(4,1))
		
		local prm = buffer(4,1):bitfield(1,1)
		local fcb_acd  = buffer(4,1):bitfield(2,1)
		local fcv_dfc  = buffer(4,1):bitfield(3,1)
		local func  = buffer(4,1):bitfield(4,4)
		
		local t1 = t0:add(msg_ctrl, buffer(4,1))
		
		t1:add(msg_ctrl_prm,buffer(4,1),tostring(prm))
		
		if prm == 1 then
			t1:add(msg_ctrl_fcb_acd,buffer(4,1)," FCB = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(4,1)," FCV = "..tostring(fcv_dfc))
			if ((fcv_dfc == 0) and (func == 0 or func == 1 or func == 4 or func == 8 or func == 9)) or 
			   ((fcv_dfc == 1) and (func == 3 or func == 10 or func == 11)) or
			   (func == 2 or (func > 5 and func < 7) or (func > 12 and func <15)) then
				t1:add(msg_ctrl_fcb_acd,buffer(4,1),iec103_prm1_func_table[func])
			end
		else
			t1:add(msg_ctrl_fcb_acd,buffer(4,1)," ACD = "..tostring(fcb_acd))
			t1:add(msg_ctrl_fcv_dfc,buffer(4,1)," DFC = "..tostring(fcv_dfc))
			
			t1:add(msg_ctrl_fcb_acd,buffer(4,1),iec103_prm0_func_table[func])
		end
		
		t0:add_le(msg_link_addr,buffer(5,iec103_link_addr_bytes))
		
		local msglen = buffer(1,1):uint()
		
		local t_asdu = t0:add(msg_ASDU,buffer(5+iec103_link_addr_bytes, msglen-1-iec103_link_addr_bytes), ">>>")
		
		local msgtypeid = buffer(5+iec103_link_addr_bytes, 1)
		local t_typeid = t_asdu:add(msg_typeid, msgtypeid)
		t_typeid:append_text(" ("..iec103_typeid_table[msgtypeid:uint()]..")")
		
		local msgvsq = buffer(6+iec103_link_addr_bytes, 1)
		local t_vsq = t_asdu:add(msg_vsq,msgvsq)
		
		if buffer(6+iec103_link_addr_bytes, 1):bitfield(0,1) == 1 then
			t_vsq:add(msg_vsq_sq, buffer(6+iec103_link_addr_bytes, 1), "1, address included in each object")
		else
			t_vsq:add(msg_vsq_sq, buffer(6+iec103_link_addr_bytes, 1), "0, only one address in the first object")
		end
		
		local msgvsq_sq = buffer(6+iec103_link_addr_bytes, 1):bitfield(0,1)
		local msgobjnum = buffer(6+iec103_link_addr_bytes, 1):bitfield(1,7)
		t_vsq:add(msg_vsq_obj_num, buffer(6+iec103_link_addr_bytes, 1), msgobjnum)
		
		local msgcotid = buffer(7+iec103_link_addr_bytes, iec103_cot_bytes):le_uint()
		local t_cot = t_asdu:add(msg_cot, buffer(7+iec103_link_addr_bytes, iec103_cot_bytes), msgcotid)
		t_cot:append_text(" ("..iec103_cot_table[msgcotid]..")")

		t_asdu:add_le(msg_comm_addr, buffer(8+iec103_link_addr_bytes, iec103_comm_addr_bytes))
		
		local func_type = buffer(9+iec103_link_addr_bytes, 1):uint()
		--t_asdu:add(msg_func_type,buffer(9+iec103_link_addr_bytes, 1), tostring(func_type) .."-"..iec103_func_type_table[func_type])
		t_asdu:add(msg_func_type,buffer(9+iec103_link_addr_bytes, 1), tostring(func_type))
		
		local info_num = buffer(10+iec103_link_addr_bytes, 1):uint()
		t_asdu:add(msg_info_num,buffer(10+iec103_link_addr_bytes, 1), info_num)
		
		Get_element(t_asdu, msgtypeid, func_type, info_num, buffer,11+iec103_link_addr_bytes)
		
		--[[
		if msgvsq_sq == 0 then
			objlen_total = msgobjnum * (iec103_obj_addr_bytes + iec103_asdu_obj_len_table[msgtypeid:uint()])
			obj_len_each = iec103_obj_addr_bytes + iec103_asdu_obj_len_table[msgtypeid:uint()]
		else
			objlen_total = iec103_obj_addr_bytes + msgobjnum * iec103_asdu_obj_len_table[msgtypeid:uint()]
			obj_len_each = iec103_asdu_obj_len_table[msgtypeid:uint()]
		end
		
		
		local obj_start_pos = 8+iec103_link_addr_bytes+iec103_comm_addr_bytes
		local obj_start_addr = buffer(8+iec103_link_addr_bytes+iec103_comm_addr_bytes, iec103_obj_addr_bytes):le_uint()
		
		local t_objs = t_asdu:add(msg_obj,buffer(obj_start_pos, objlen_total),">>> total "..msgobjnum)
		local obj_addr = 0
		
		for cnt = 1, msgobjnum, 1 do
			
			--if VSQ SQ = 0, get the address from each object 
		    if msgvsq_sq == 0 then
				local t_obj_single = t_objs:add(msg_obj_single,buffer(obj_start_pos, obj_len_each), cnt)
				obj_addr = buffer(obj_start_pos, iec103_obj_addr_bytes):le_uint()
				t_obj_single:append_text(" , address: "..obj_addr)
				
				t_obj_single:add_le(msg_obj_addr, buffer(obj_start_pos, iec103_obj_addr_bytes))
				--t_obj_single:add(msg_obj_value,buffer(obj_start_pos+iec103_obj_addr_bytes, iec103_asdu_obj_len_table[msgtypeid:uint()]),"TRUE")
				Add_Object_Value(t_obj_single,msgtypeid, buffer, obj_start_pos+iec103_obj_addr_bytes)
				
			else
				
				--if VSQ SQ = 1, get the address from the first object
				if cnt == 1 then
					local t_obj_single = t_objs:add(msg_obj_single,buffer(obj_start_pos, obj_len_each+iec103_obj_addr_bytes), cnt)
					obj_addr = buffer(obj_start_pos, iec103_obj_addr_bytes):le_uint()
					t_obj_single:append_text(" , address: "..obj_addr)
				
					t_obj_single:add_le(msg_obj_addr, buffer(obj_start_pos, iec103_obj_addr_bytes))
					--t_obj_single:add(msg_obj_value,buffer(obj_start_pos+iec103_obj_addr_bytes, iec103_asdu_obj_len_table[msgtypeid:uint()]),"TRUE")
					Add_Object_Value(t_obj_single,msgtypeid, buffer, obj_start_pos+iec103_obj_addr_bytes)
					
				--update the following object address 
				else
					local t_obj_single = t_objs:add(msg_obj_single,buffer(obj_start_pos, obj_len_each), cnt)
					obj_addr = obj_addr + 1
					t_obj_single:append_text(" , address: "..obj_addr)
				
					t_obj_single:add(msg_obj_addr, buffer(obj_start_pos, iec103_asdu_obj_len_table[msgtypeid:uint()]),obj_addr)
					--t_obj_single:add(msg_obj_value,buffer(obj_start_pos, iec103_asdu_obj_len_table[msgtypeid:uint()]),"TRUE")
					Add_Object_Value(t_obj_single,msgtypeid, buffer, obj_start_pos)
					
				end
			end
			
			--if VSQ SQ = 1, the object address included in the first object
			--increasement also need including the object address width
			if msgvsq_sq == 1 and cnt == 1 then
				obj_start_pos = obj_start_pos + iec103_obj_addr_bytes + iec103_asdu_obj_len_table[msgtypeid:uint()]
			else
				obj_start_pos = obj_start_pos + obj_len_each
			end
		
		end
		
		--]]
		
		t0:add(msg_checksum, buffer(4 + msglen,1))
		t0:add(msg_end, buffer(5 + msglen,1))
		
		local temp = 100
		t0:add(msg_debug,temp)
		
	elseif msg_start == 229 then
		local t0 = tree:add(iec103,buffer(), "IEC 60870-5-103 Linke layer ACK")
	end
	
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 22403
tcp_table:add(22403,iec103)