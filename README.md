# Keyboard Wanderer
Keyboard Wanderer (KBW) is a high performance generator of characters strings
written in C, based on the idea that passwords may be created by following some
patterns on a keyboard. By “walking” on their keyboard, users can generate a
seemingly random sequence of characters that is easy to remember when needed by
just recalling the rules that define the path. Although these kinds of passwords
are strictly tight to a specific keyboard layout, since changing the layout
would change the path required to generate the same sequence of characters, they
may represent, at least for non technical users, a valid alternative to password
generators or other automatic tools. KBW simulates this method of generating
sequences of characters by reading a configuration file that defines a keyboard,
which is internally represented as a directed graph, and performing a
Depth-First Search on it starting from one or more keys. This allows the
generation of dictionaries containing path-based strings that can be used with
other tools to perform dictionary-based attacks. Other than the generation, the
software is also equipped with a dry-run execution mode that gives an estimate
of the total number of generated strings for a selected configuration, and a
restart mode that allows to continue the generation starting from a previously
generated string.