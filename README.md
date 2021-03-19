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
