     1→WinMTR (Redux)
     2→==============
     3→**WinMTR (Redux)** in an extended fork of [Appnor's WinMTR](http://winmtr.net/) ([sourceforge](http://sourceforge.net/projects/winmtr/)) <br>
     4→with IPv6 support and other different enhancements and bug fixes
     5→
     6→### Download (binaries)
     7→* [**view all available**](https://github.com/White-Tiger/WinMTR/releases)
     8→
     9→#### Differences to [WinMTR](http://winmtr.net/) 0.98
    10→- `[x]` - removed Windows 2000 support <br>
    11→- `[x]` + added IPv6 support <br>
    12→- `[x]` + clickable entries when stopped.. *(why the heck wasn't it possible before?)* <br>
    13→- `[x]` * added start delay of about 30ms for each hop *(870ms before the 30th hop gets queried) <br>
    14→this should improve performance and reduces network load* <br>
    15→- `[x]` ! fixed trace list freeze *(list didn't update while tracing, happens when tracing just one hop)* <br>
    16→- `[x]` * theme support *(more fancy look :P)* <br>
    17→- ~~`[ ]` + remembers window size~~ <br>
    18→- `[ ]` ! CTRL+A works for host input <br>
    19→- `[ ]` + host history: pressing del key or right mouse will remove selected entry <br>
    20→- `[ ]` * new icon <br>
    21→
    22→### Requirements
    23→* Windows XP+ *(Windows 2000 support can be added on request, but IPv6 will not work)*
    24→* Microsoft Visual C++ 2010 Redistributables
    25→([32bit](http://microsoft.com/en-us/download/details.aspx?id=5555) |
    26→[64bit](http://microsoft.com/en-us/download/details.aspx?id=14632)) or use static build
    27→
    28→### About me / why I decided to create this fork
    29→There isn't that much to say actually, I've been using IPv6 for a few years now thanks to [**SixXS**](http://sixxs.net/)
    30→and it always annoyed me that WinMTR couldn't handle IPv6... finally my ISP got some sort of IPv6 beta test.
    31→And that's what I wanted to compare: native vs SixXS with long-term trace routes such as those WinMTR provides. <br>
    32→Since there wasn't any WinMTR build with IPv6, I decided to do it myself ;) The result can be seen here :P <br>
    33→*(after 1 day for IPv6, and 2 additional days to fix other stuff and polishing)*
    34→
    35→**If you're looking for an alternative** *(not meant for long-term traces)* there's [**vTrace**](http://vtrace.pl).
    36→It's some really interesting piece of Software ;) *(with more then just trace routes)*
    37→~~~~
    38→
