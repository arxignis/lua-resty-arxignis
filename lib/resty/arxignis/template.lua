local template = {_TYPE='module', _NAME='arxignis.template', _VERSION='1.0-0'}

function template.compile(template_str, args)

    for k, v in pairs(args) do
        local var = "{{" .. k .. "}}"
        template_str = template_str:gsub(var, v)
    end

    return template_str
end

return template
