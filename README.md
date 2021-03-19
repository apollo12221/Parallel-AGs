# Parallel-AGs
An R package for parallel Attack Graph generation and analysis

## Description

This is an R package for Attack Graph (AG) generation and analysis. Functions for AG generation take as input the target network modeling and vulnerability
information and generate the output AG with node and edges reported. Functions for AG analysis takes as input the AG node and edge matrix created by AG 
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
> myAG <- ag_generator()
```
A successful installation should obtain the following results:

```
> myAG$nNodes
> 11
> myAG$nEdges
> 16

```

## Technical support

- Please read this [paper](https://ieeexplore.ieee.org/abstract/document/8855310) for the design details of our parallel attack graph generator
- Please contact mingfinkli@gmail.com if you have further questions
