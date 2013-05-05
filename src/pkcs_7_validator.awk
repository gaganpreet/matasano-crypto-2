#!/usr/bin/awk -f
function ord(c)
{
    for (i = 0; i < 255; ++i)
        if (sprintf("%c", i) == c)
            return i
}

function char_at(s, n)
{
    return substr(line, n, 1)
}

{
    line = $0;
    last = substr(line, length(line), 1)
    ascii_last = ord(last)

    for (i = length(line); i > length(line) - ascii_last; --i) 
        if (char_at(s, i) != last)
        {
            print "Bad padding detected for line ", NR
            next
        }
    print "Correct padding detected for line ", NR
}
