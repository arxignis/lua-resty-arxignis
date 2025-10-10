--[[
    Binary tree implementation for efficient IPv4 and IPv6 subnet search.
    Designed for scenarios with a large number of subnets, enabling quick checks
    to determine if an IP address belongs to a specific subnet.

    Features:
    - Supports both IPv4 and IPv6 addresses.
    - Efficient insertion and search operations using binary trees.
    - Handles CIDR notation for subnet masks.

    Created by: bnch.dan
    Created on: 2025-03-21
    GitHub: https://github.com/bnchdan
]]
-- Modified by: Arxignis
-- Modified on: 2025-09-18
-- GitHub: https://github.com/arxignis/lua-resty-arxignis
-- Original code from: https://github.com/bnchdan/ipinsubnet

local bit = require("bit")

local LookUp = {}
function LookUp.getDec()
    return {
        ["0"] = 0,
        ["1"] = 1,
        ["2"] = 2,
        ["3"] = 3,
        ["4"] = 4,
        ["5"] = 5,
        ["6"] = 6,
        ["7"] = 7,
        ["8"] = 8,
        ["9"] = 9,
        ["a"] = 10,
        ["b"] = 11,
        ["c"] = 12,
        ["d"] = 13,
        ["e"] = 14,
        ["f"] = 15
    }
end

local BinaryTreeNode = {}
BinaryTreeNode.__index = BinaryTreeNode

function BinaryTreeNode:new(value)
    local node = {value = value, left = nil, right = nil}
    setmetatable(node, BinaryTreeNode)
    return node
end

local BinaryTree = {}
BinaryTree.__index = BinaryTree
BinaryTree.lookupIPv6Dec = LookUp.getDec()

function BinaryTree:new()
    local tree = {
        root = BinaryTreeNode:new('*') -- root node will have the value *
    }
    setmetatable(tree, BinaryTree)
    return tree
end

--[[
        Insert IPv4 address into the tree
        @param value string IPv4 address
        @param node root
        @param num_bits -mask
    ]] --
function BinaryTree.insertIPv4(value, node, num_bits)
    local dec = 0
    local curent_num_bits = 0
    local j = 1
    local size_value = #value
    local c
    for i = 1, size_value do
        c = value:sub(i, i)

        -- new byte
        if c == "." then
            dec = value:sub(j, i - 1)
            j = i + 1
            goto process_byte
        end

        -- end of IP
        if i == size_value then
            dec = value:sub(j, i)
            goto process_byte

        end

        -- go to the next character
        goto continue_insert_IPv4

        ::process_byte::
        -- ngx.say("dec : ", dec)
        local mbit
        for k = 7, 0, -1 do

            -- get most significant bit
            mbit = bit.band(bit.rshift(dec, k), 1)
            -- ngx.say("  bin : ", mbit)

            if mbit == 0 then
                if node.left == nil then
                    node.left = BinaryTreeNode:new(mbit)
                end
                -- ngx.say("  bin : ", mbit)
                -- go to the next node
                node = node.left
            else
                if node.right == nil then
                    node.right = BinaryTreeNode:new(mbit)
                end
                -- ngx.say("  bin : ", mbit)
                -- go to the next node
                node = node.right
            end

            curent_num_bits = curent_num_bits + 1
            -- stop if we reach the mask
            if curent_num_bits == num_bits then
                -- node.left = BinaryTreeNode:new("*")
                -- ngx.say("curent_num_bits : ", curent_num_bits)
                return
            end
        end

        ::continue_insert_IPv4::
    end
end

--[[
        Search IPv4 address in the tree
        @param value string IPv4 address
        @param node root
        return boolean true if found, false otherwise
    ]] --
function BinaryTree.searchIPv4(value, node)
    if node.left == nil and node.right == nil then
        -- tree is empty
        return false
    end
    local dec
    local j = 1
    local size_value = #value
    local c
    for i = 1, size_value do
        c = value:sub(i, i)

        -- new byte
        if c == "." then
            dec = value:sub(j, i - 1)
            j = i + 1
            goto search_byte
        end

        -- end of IP
        if i == size_value then
            dec = value:sub(j, i)
            goto search_byte

        end

        -- go to the next character
        goto continue_search_IPv4

        ::search_byte::
        -- ngx.say("dec : ", dec)
        local mbit
        for k = 7, 0, -1 do

            -- get most significant bit
            mbit = bit.band(bit.rshift(dec, k), 1)

            if node.left == nil and node.right == nil then
                -- ngx.say("is in tree")
                return true
            end

            if mbit == 0 then
                if node.left == nil then
                    -- ngx.say("is not in tree 0")
                    return false
                end
                node = node.left
            else
                if node.right == nil then
                    -- ngx.say("is not in tree 1")
                    return false
                end
                node = node.right
            end

        end

        ::continue_search_IPv4::
    end
end

--[[
    Insert IPv6 address into the tree
    @param value string IPv6 address
    @param node root
    @param num_bits -mask
]]
function BinaryTree.insertIPv6(value, node, num_bits)

    local dec, mbit
    local num4_hex = 0
    local j = 1
    local current_num_of_groups = 0
    local current_num_of_bits = 0
    local END = 0
    local decompressed = ""
    local mhex
    -- ngx.say("value : ", value)
    for i = 1, #value do
        -- stop if we reach the mask
        -- if current_num_of_bits > num_bits then
        --     ngx.say("curent_num_bits : ", current_num_of_bits)
        --     return
        -- end
        mhex = value:sub(i, i)

        if i == #value then
            END = i
            if mhex == ":" then goto process_insert_group end
            num4_hex = num4_hex + 1
            goto process_insert_group
        end

        if mhex == ":" then
            if i == 1 then -- skip if starts with :, eg. ::1
                goto continue_insert_IPv6
            end
            END = i - 1
            goto process_insert_group
        end

        num4_hex = num4_hex + 1
        goto continue_insert_IPv6

        ::process_insert_group::
        current_num_of_groups = current_num_of_groups + 1

        if current_num_of_groups > 1 then
            decompressed = decompressed .. ":"
        end

        -- case 1 - not compressed
        if num4_hex == 4 then
            for k = j, END do

                mhex = value:sub(k, k)
                -- append mhex
                dec = BinaryTree.lookupIPv6Dec[mhex]
                node, current_num_of_bits =
                    BinaryTree.append4Bits(node, dec, num_bits,
                                           current_num_of_bits)
                if current_num_of_bits == num_bits then -- stop if we reach the mask
                    return
                end
            end

        end

        -- case 2  - on ::
        if num4_hex == 0 then
            local num_of_groups = 0
            -- search number of : after ::
            for k = i, #value do
                mhex = value:sub(k, k)
                if mhex == ":" then
                    if k == #value then -- if ends with :
                        break
                    end

                    num_of_groups = num_of_groups + 1
                end
            end
            local num_of_groups_to_add =
                8 - current_num_of_groups - num_of_groups + 1
            -- apend zeros
            for k = 1, num_of_groups_to_add do
                for i = 1, 4 do
                    node, current_num_of_bits =
                        BinaryTree.append4Bits(node, 0, num_bits,
                                               current_num_of_bits)
                    if current_num_of_bits == num_bits then -- stop if we reach the mask
                        return
                    end
                end
            end

            -- case 3 - not 4 hex group
        elseif num4_hex < 4 then
            -- append 0
            for i = num4_hex, 4 - 1 do
                -- apend 0

                node, current_num_of_bits =
                    BinaryTree.append4Bits(node, 0, num_bits,
                                           current_num_of_bits)
                if current_num_of_bits == num_bits then -- stop if we reach the mask
                    return
                end
            end
            for k = j, END do
                mhex = value:sub(k, k)
                -- append mhex
                dec = BinaryTree.lookupIPv6Dec[mhex]
                node, current_num_of_bits =
                    BinaryTree.append4Bits(node, dec, num_bits,
                                           current_num_of_bits)
                if current_num_of_bits == num_bits then -- stop if we reach the mask
                    return
                end
            end
        end
        num4_hex = 0
        j = i + 1

        ::continue_insert_IPv6::
    end

end

--[[
    Append 4 bits to the tree. Called from insertIPv6
    @param node
    @param value int value of the hex, max 4 bits
    @param num_bits int
    @param current_num_of_bits int
    return next node and the current number of bits
]]
function BinaryTree.append4Bits(node, value, num_bits, current_num_of_bits)
    local mbit
    for i = 3, 0, -1 do

        -- append 0
        mbit = bit.band(bit.rshift(value, i), 1)
        -- ngx.say("  bin : ", mbit)

        if mbit == 0 then
            if node.left == nil then
                node.left = BinaryTreeNode:new(mbit)
            end
            -- ngx.say("  bin : ", mbit)
            -- go to the next node
            node = node.left
        else
            if node.right == nil then
                node.right = BinaryTreeNode:new(mbit)
            end
            -- ngx.say("  bin : ", mbit)
            -- go to the next node
            node = node.right
        end

        current_num_of_bits = current_num_of_bits + 1

        -- stop if we reach the mask
        if current_num_of_bits == num_bits then break end
    end
    return node, current_num_of_bits
end

--[[
    Search IPv6 address in the tree
    @param value string IPv6 address
    @param node root
    return boolean true if found, false otherwise
]]
function BinaryTree.searchIPv6(value, node)
    if node.left == nil and node.right == nil then
        -- tree is empty
        return false
    end

    local dec, mbit
    local num4_hex = 0
    local j = 1
    local current_num_of_groups = 0
    local current_num_of_bits = 0
    local END = 0
    local decompressed = ""
    local mhex
    -- ngx.say("value : ", value)
    for i = 1, #value do
        -- stop if we reach the mask
        -- if current_num_of_bits > num_bits then
        --     ngx.say("curent_num_bits : ", current_num_of_bits)
        --     return
        -- end
        mhex = value:sub(i, i)

        if i == #value then
            END = i
            if mhex == ":" then goto process_search_group end
            num4_hex = num4_hex + 1
            goto process_search_group
        end

        if mhex == ":" then
            if i == 1 then -- skip if starts with :, eg. ::1
                goto continue_search_IPv6
            end
            END = i - 1
            goto process_search_group
        end

        num4_hex = num4_hex + 1
        goto continue_search_IPv6

        ::process_search_group::
        current_num_of_groups = current_num_of_groups + 1

        if current_num_of_groups > 1 then
            decompressed = decompressed .. ":"
        end

        -- case 1 - not compressed
        if num4_hex == 4 then
            for k = j, END do

                mhex = value:sub(k, k)
                -- append mhex
                dec = BinaryTree.lookupIPv6Dec[mhex]
                node, res = BinaryTree.search4Bits(node, dec)

                if res ~= nil then return res end
            end

        end

        -- case 2  - ::
        if num4_hex == 0 then
            local num_of_groups = 0
            -- search number of : after ::
            for k = i, #value do
                mhex = value:sub(k, k)
                if mhex == ":" then
                    if k == #value then -- if ends with :
                        break
                    end

                    num_of_groups = num_of_groups + 1
                end
            end
            local num_of_groups_to_add =
                8 - current_num_of_groups - num_of_groups + 1
            -- apend zeros
            for k = 1, num_of_groups_to_add do
                for i = 1, 4 do

                    -- apend 0
                    node, res = BinaryTree.search4Bits(node, 0)

                    if res ~= nil then return res end
                end
            end

            -- case 3 - not 4 hex
        elseif num4_hex < 4 then
            -- append 0
            for i = num4_hex, 4 - 1 do
                -- apend 0

                node, res = BinaryTree.search4Bits(node, 0)
                if res ~= nil then return res end
            end
            for k = j, END do

                mhex = value:sub(k, k)
                -- append mhex
                node, res = BinaryTree.search4Bits(node, dec)
                if res ~= nil then return res end
            end
        end
        num4_hex = 0

        j = i + 1

        ::continue_search_IPv6::
    end
end

--[[
    Search 4 bits in the tree. Called from searchIPv6
    @param value int value of the hex, max 4 bits
    @param node
    return next node and the result if found
]]
function BinaryTree.search4Bits(node, value)
    local mbit
    for i = 3, 0, -1 do
        -- append 0
        mbit = bit.band(bit.rshift(value, i), 1)
        if node.left == nil and node.right == nil then
            -- ngx.say("is in tree")
            return node, true
        end

        if mbit == 0 then
            if node.left == nil then
                -- ngx.say("is not in tree")
                return node, false
            end
            node = node.left
        else
            if node.right == nil then
                -- ngx.say("is not in tree")
                return node, false
            end
            node = node.right
        end
    end

    return node, nil
end

--[[
    Decompress IPv6 address alghortihm ussed in the insertIPv6 and searchIPv6
    @param value string IPv6 address
    @return string decompressed IPv6 address
        e.g. 2001:0db8::0001 -> 2001:0db8:0000:0000:0000:0000:0000:0001
]]
function BinaryTree.decompressedIPv6(value)
    -- ngx.say(value)
    -- ngx.say(num_bits)
    local dec, mbit
    local num4_hex = 0
    local j = 1
    local current_num_of_groups = 0
    local END = 0
    local decompressed = ""
    local mhex
    -- ngx.say("value : ", value)
    for i = 1, #value do
        mhex = value:sub(i, i)

        if i == #value then
            END = i
            if mhex == ":" then
                -- current_num_of_groups = current_num_of_groups - 1 -- for ::
                goto process_decompressed_group
            end
            num4_hex = num4_hex + 1
            goto process_decompressed_group
        end

        if mhex == ":" then
            if i == 1 then -- skip if starts with :, eg. ::1
                goto continue_decompressed_IPv6
            end
            END = i - 1
            goto process_decompressed_group
        end

        num4_hex = num4_hex + 1
        goto continue_decompressed_IPv6

        ::process_decompressed_group::
        current_num_of_groups = current_num_of_groups + 1

        if current_num_of_groups > 1 then
            decompressed = decompressed .. ":"
        end
        -- not compressed
        if num4_hex == 4 then
            for k = j, END do
                mhex = value:sub(k, k)
                -- ngx.say("mhex : ", mhex)
                decompressed = decompressed .. mhex
            end
        end

        -- found ::
        if num4_hex == 0 then
            -- ngx.say("found ::")
            local num_of_groups = 0
            -- search number of : after ::
            for k = i, #value do
                mhex = value:sub(k, k)
                if mhex == ":" then
                    if k == #value then -- if ends with :
                        break
                    end

                    num_of_groups = num_of_groups + 1
                end
            end
            -- ngx.say("num_of_groups : ", num_of_groups)
            -- ngx.say("current_num_of_groups : ", current_num_of_groups)
            local num_of_groups_to_add =
                8 - current_num_of_groups - num_of_groups + 1

            -- ngx.say("num_of_groups_to_add : ", num_of_groups_to_add)

            -- apend zeros
            for k = 1, num_of_groups_to_add do
                for i = 1, 4 do
                    -- ngx.say("i : ", 0)
                    decompressed = decompressed .. "0"
                end
                if k < num_of_groups_to_add then
                    decompressed = decompressed .. ":"
                end
            end

        elseif num4_hex < 4 then
            -- append 0
            for i = num4_hex, 4 - 1 do
                -- ngx.say("i : ", 0)
                decompressed = decompressed .. "0"
            end
            for k = j, END do
                mhex = value:sub(k, k)
                -- ngx.say("mhex : ", mhex)
                decompressed = decompressed .. mhex
            end
        end
        num4_hex = 0

        j = i + 1

        ::continue_decompressed_IPv6::
    end
    -- ngx.say("compresed: ", value)
    -- ngx.say("decompressed : ", decompressed)
    return decompressed
end

--[[
    Print the tree
    @param node root
    @param delimiter string
    @param space string
    @param index int
]]
function BinaryTree.printTree(node, delimiter, space, index)
    if node == nil then return end

    if (space == nil) then space = "" end

    if (delimiter == nil) then delimiter = "..." end

    if (index == nil) then index = 0 end

    ngx.say(space .. node.value)
    if index % 8 == 0 and index ~= 0 then
        ngx.say(space .. "............8bits delimiter............")
    end

    BinaryTree.printTree(node.left, delimiter, space .. delimiter, index + 1)
    BinaryTree.printTree(node.right, delimiter, space .. delimiter, index + 1)
end

local IPInSubnet = {treeIPv4 = nil, treeIPv6 = nil}
IPInSubnet.__index = IPInSubnet
-- Constructor
function IPInSubnet:new()
    local o = {treeIPv4 = BinaryTree:new(), treeIPv6 = BinaryTree:new()}
    setmetatable(o, self)
    return o
end

function IPInSubnet:isValidIPv4(ip)
    -- Check if the IP matches the IPv4 pattern
    local octets = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
    if #octets ~= 4 then return false end

    -- Ensure each octet is within the valid range (0-255)
    for _, octet in ipairs(octets) do
        local num = tonumber(octet)
        if not num or num < 0 or num > 255 then return false end
    end

    return true
end

function IPInSubnet:isValidIPv6(ip)
    ip = self.treeIPv6.decompressedIPv6(ip)
    -- Check if the IP matches the IPv6 pattern
    local segments = {
        ip:match(
            "([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)")
    }
    if #segments ~= 8 then return false end

    -- Ensure each segment is a valid hexadecimal number
    for _, segment in ipairs(segments) do
        if not tonumber(segment, 16) then return false end
    end

    return true
end

function IPInSubnet:addSubnet(cidr)
    -- --split the subnet and mask
    local subnet, maskBits = cidr:match("([^/]+)/(%d+)")

    if not subnet or not maskBits then return false, "Invalid CIDR" end

    maskBits = tonumber(maskBits)

    if self:isValidIPv4(subnet) then
        -- ngx.say("IPv4 subnet ", subnet)
        if maskBits > 32 or maskBits < 1 then
            return false, "Invalid mask"
        end

        self.treeIPv4.insertIPv4(subnet, self.treeIPv4.root, maskBits)

        return true
    end

    if self:isValidIPv6(subnet) then
        -- ngx.say("IPv6 subnet")

        if maskBits > 128 or maskBits < 1 then
            return false, "Invalid mask"
        end

        self.treeIPv6.insertIPv6(subnet, self.treeIPv6.root, maskBits)
        return true
    end

    return false
end

function IPInSubnet:isInSubnets(ip)
    if ip:find(".", 1, true) then -- is IPv4
        -- ngx.say("IPv4#", ip)
        return self.treeIPv4.searchIPv4(ip, self.treeIPv4.root)
    end
    -- ngx.say("IPv6")
    return self.treeIPv6.searchIPv6(ip, self.treeIPv6.root)
end

function IPInSubnet:isInSubnetsStrict(ip)
    if self:isValidIPv4(ip) then
        -- ngx.say("IPv4")
        return self.treeIPv4.searchIPv4(ip, self.treeIPv4.root)
    end

    if self:isValidIPv6(ip) then
        -- ngx.say("IPv6")
        return self.treeIPv6.searchIPv6(ip, self.treeIPv6.root)
    end

    -- invalid format
    return false
end

return IPInSubnet
