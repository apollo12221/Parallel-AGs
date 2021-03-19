# Parallel-AGs
An R package for parallel Attack Graph generation and analysis

## Description

This is an R package for Attack Graph (AG) generation and analysis. Functions for AG generation takes as input the target network modeling and vulnerability
information and generates the output AG with node and edges reported. Functions for AG analysis takes as input the AG node and edge matrix created by AG 
generation functions and performs centrality and other analyses. Functions for network creation creates target networks for the AG generation functions.

## System requirement

- 8 GB memory (to run with large input data)
- Debian and Ubuntus
- R (>=3.5)
  - dependencies igraph and ggplot2

## How to use the code

preparation: R and dependencies

1. Clone this repo to your system, then run `setup.sh`:

```
$ ./setup.sh
```

2. Open R in terminal (or rstudio), and verify the installation by

```
$ R
> library(attackgraph)
> ag_generator()

A successful installation should see the following printout:

```
[1] "/home/ming/R/x86_64-pc-linux-gnu-library/3.6/attackgraph/lib/app.so"
[1] "R: shared object loading successful!"
[1] "R: call the .C function to invoke AG generator function!"
[1] "!!"

------------>>>>>>>>>>> C execution starts ........................
>>>>>>>>>>> step 1: check control parameters ...
Number of threads: 1, initial size of the master frontier: 1
The file name is /home/ming/R/x86_64-pc-linux-gnu-library/3.6/attackgraph/extdata/example.data
>>>>>>>>>>>>> Step 1: done

>>>>>>>>>>>>>>>>> Step 2: load in nm and xp
The last symbol from the input file is �
The length of the input string is 1366
The time to load the input string is 0.072000 ms.<------
====== The contents in inputStr: ======
INSERT INTO asset VALUES
(0, 'host0'),
(1, 'host1'),
(2, 'host2'),
(3, 'host3'),
(4, 'host4');
INSERT INTO quality VALUES
(0, 'root', '=', 'true'),
(1, 'os', '=', 'v1'),
(2, 'os', '=', 'v2'),
(3, 'os', '=', 'v3'),
(4, 'os', '=', 'v4');
INSERT INTO topology VALUES
(0, 1, '->', 'conn', '', ''),
(0, 4, '->', 'conn', '', ''),
(1, 2, '->', 'conn', '', ''),
(2, 3, '->', 'conn', '', ''),
(3, 2, '->', 'conn', '', ''),
(4, 3, '->', 'conn', '', '');
INSERT INTO exploit VALUES
(0, 'e0', 2),
(1, 'e1', 2),
(2, 'e2', 2),
(3, 'e3', 2);
INSERT INTO exploit_precondition VALUES
(0, 0, 0, 0, 0, 'root', 'true', '=', '(null)'),
(1, 0, 0, 1, 0, 'os', 'v1', '=', '(null)'),
(2, 0, 1, 0, 1, 'conn', '', '', '->'),
(3, 1, 0, 0, 0, 'root', 'true', '=', '(null)'),
(4, 1, 0, 1, 0, 'os', 'v2', '=', '(null)'),
(5, 1, 1, 0, 1, 'conn', '', '', '->'),
(6, 2, 0, 0, 0, 'root', 'true', '=', '(null)'),
(7, 2, 0, 1, 0, 'os', 'v3', '=', '(null)'),
(8, 2, 1, 0, 1, 'conn', '', '', '->'),
(9, 3, 0, 0, 0, 'root', 'true', '=', '(null)'),
(10, 3, 0, 1, 0, 'os', 'v4', '=', '(null)'),
(11, 3, 1, 0, 1, 'conn', '', '', '->');
INSERT INTO exploit_postcondition VALUES
(0, 0, 0, 1, 0, 'root', 'true', '=', '(null)', 'insert'),
(1, 1, 0, 1, 0, 'root', 'true', '=', '(null)', 'insert'),
(2, 2, 0, 1, 0, 'root', 'true', '=', '(null)', 'insert'),
(3, 3, 0, 1, 0, 'root', 'true', '=', '(null)', 'insert');

=======================================
>>>>>>>>>>>> Step 2: done

>>>>>>>>>>>>>>>>> Step 3: parse the input model
The 6 index values are: 0 95 236 444 527 1093 
----------Parse the asset string---------
---number of assets 5
id: 0 name: host0
id: 1 name: host1
id: 2 name: host2
id: 3 name: host3
id: 4 name: host4
-----------Parse the quality string---------
---number of initial qualities 5
asset_id: 0 property: root op: = value: true
asset_id: 1 property: os op: = value: v1
asset_id: 2 property: os op: = value: v2
asset_id: 3 property: os op: = value: v3
asset_id: 4 property: os op: = value: v4
-----------Parse the topology string---------
---number of topologies 6
0||1||->||conn||||
0||4||->||conn||||
1||2||->||conn||||
2||3||->||conn||||
3||2||->||conn||||
4||3||->||conn||||
-----------Parse the exploit string---------
---number of exploits 4
id: 0 name: e0 params: 2
id: 1 name: e1 params: 2
id: 2 name: e2 params: 2
id: 3 name: e3 params: 2
-----------Parse the exploit precondition string---------
---number of precondition entries 12
0||0||0||0||0||root||true||=||(null)
1||0||0||1||0||os||v1||=||(null)
2||0||1||0||1||conn||||||->
3||1||0||0||0||root||true||=||(null)
4||1||0||1||0||os||v2||=||(null)
5||1||1||0||1||conn||||||->
6||2||0||0||0||root||true||=||(null)
7||2||0||1||0||os||v3||=||(null)
8||2||1||0||1||conn||||||->
9||3||0||0||0||root||true||=||(null)
10||3||0||1||0||os||v4||=||(null)
11||3||1||0||1||conn||||||->
-----------Parse the exploit postcondition string---------
End of the entire string
---number of postcondition entries 4
0||0||0||1||0||root||true||=||(null)||insert
1||1||0||1||0||root||true||=||(null)||insert
2||2||0||1||0||root||true||=||(null)||insert
3||3||0||1||0||root||true||=||(null)||insert
>>>>>>>>>>>>>>>>> Step 3: done

>>>>>>>>>>>>>>>>> Step 4: create an AG instance and populate it with input data
--- The size of the created AG instance is 2300089632

--- Hashing all facts ...
number of unique asset facts 5
number of unique facts 9
number of unique precond facts 9
number of unique exploit facts 4
--- Hashing done !!!

--- Populating the AG instance with initial data ... 
#digitized qualities: 
0 0 0 1 0.000000
1 2 0 3 0.000000
2 2 0 4 0.000000
3 2 0 5 0.000000
4 2 0 6 0.000000
#digitized topologies: 
0 1 7 0
0 4 7 0
1 2 7 0
2 3 7 0
3 2 7 0
4 3 7 0
#digitized exploits: 
0 0 2 2 1 1 0
1 1 2 2 1 1 0
2 2 2 2 1 1 0
3 3 2 2 1 1 0
#sample exploit-precondition qualities
Exploit 0 --- 0 0 1 0 0 0.000000
Exploit 1 --- 0 0 1 0 0 0.000000
Exploit 2 --- 0 0 1 0 0 0.000000
Exploit 3 --- 0 0 1 0 0 0.000000
#sample exploit-postcondition qualities
Exploit 0 --- 1 0 1 0 0 0.000000
Exploit 1 --- 1 0 1 0 0 0.000000
Exploit 2 --- 1 0 1 0 0 0.000000
Exploit 3 --- 1 0 1 0 0 0.000000
--- Populating done !!!
>>>>>>>>>>>>>>>>> Step 4: done

>>>>>>>>>>>>>>>>> Step 5: generate the AG

 ############## Attack graph generation begins ############# 

--->>> Single Threaded Phase .........................
--->>> hashvalue of the root node: 3715710123135895400
--->>> hashAddr of the root node: 4308237
--->>> hashing the root node took 0.037000 ms
--->>> Initial size of the main thread frontier: 0
--->>> Enqueuing the root node into the main thread frontier is successful? Yes(1), No(0) --- 1
--->>> The current size fo the main thread frontier: 1
--->>> Node hashTable size in bytes: 320000528
--->>> Attack graph instance size in bytes:  2300089632
--->>> Main thread frontier size in bytes: 2000016
--->>> Current number of discovered nodes in the attack graph instance: 1
--->>> Current number of nodes in the main thread frontier: 1
--->>> Initial expansion by the main thread is done.
--->>> The preset minimum number of nodes in the main thread frontier is 1
--->>> The actual number of nodes in the main thread frontier is 1
--->>> The preset number of OpenMP threads is 1

--->>> Multi-threaded Phase ...........................
Thread 0 is expanding node 0
################ The target attack graph has been generated successfully #################

--->>> Number of nodes expanded by main threads:
0
--->>> Number of nodes expanded by each parallel thread:
-- Thread 0 expanded 11 nodes.

--->>> The number of nodes in the attack graph is 11
--->>> The number of edges in the attack graph is 16
--->>> The attack graph generation took 0.000613 seconds
Report by the C program: 
The number of nodes in the attack graph is 11
The number of edges in the attack graph is 16
Now transfer edge data to R ...
Transfer is done!
>>>>>>>>>>>>>>>>> Step 5: done
--->>> C execution complete, return to R IDE ......



[1] ""
[1] "R: Done !!!"
[1] "R: the number of edges in the AG is 16"
[1] "R: The number of nodes in the AG is 11"
$node.matrix
      node_id num_qualities num_topologies
 [1,]       0             5              6
 [2,]       1             6              6
 [3,]       2             6              6
 [4,]       3             7              6
 [5,]       4             7              6
 [6,]       5             7              6
 [7,]       6             8              6
 [8,]       7             8              6
 [9,]       8             8              6
[10,]       9             8              6
[11,]      10             9              6

$edge.matrix
      edge_id from_node to_node exploit_id asset_id
 [1,]       0         0       1          0        1
 [2,]       1         0       2          3        4
 [3,]       2         1       3          1        2
 [4,]       3         1       4          3        4
 [5,]       4         2       4          0        1
 [6,]       5         2       5          2        3
 [7,]       6         3       6          2        3
 [8,]       7         3       7          3        4
 [9,]       8         4       7          1        2
[10,]       9         4       8          2        3
[11,]      10         5       8          0        1
[12,]      11         5       9          1        2
[13,]      12         6      10          3        4
[14,]      13         7      10          2        3
[15,]      14         8      10          1        2
[16,]      15         9      10          0        1

$nNodes
[1] 11

$nEdges
[1] 16

```


## Technical support

- Please read this [paper](https://ieeexplore.ieee.org/abstract/document/8855310) for the design details of our parallel attack graph generator
- Please contact mingfinkli@gmail.com if you have further questions
