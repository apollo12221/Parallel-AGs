# R code to interface with the CUDA-based attack graph generator
# author: Ming Li
# 3/18/2021

# .First.lib <- function(lib,pkg){
#   library.dynam("app.so", pkg, lib)
# }

#' generate an Attack Graph
#'
#' This function loads a file describing a target network as input,
#' and generates its Attack Graph with nodes, edges, number of nodes
#' and number of edges reported.
#'
#' @param filename.str The name of the file that describes a target network. Default an example file describing a network with 4 vulnerable hosts.
#' @param numThreads The number of threads that accelerate Attack Graph generation. Default 1
#' @param initQSize The number of initial nodes for multiple threads to expand, and must be no less than the number of threads. Default 1
#' @param so.str The name of the shared object (.so) file for accelerating Attack Graph generation. Default "app.so"
#' @return A list of node matrix, edge matrix, number of nodes and number of edges
#' @details The target network described by the file filename.str should follow a predefined format. Invoke format_ref()
#' function to refer to an example
#' @export
#' @examples ag_generator() # all arguments on default to generate AG for a built-in example target network
#'
#' @examples ag_generator(create_network(5), 1, 1) # create a target network with 5 vulnerable hosts and generate the AG
#' with 1 thread and 1 initial node.
#'
#' @examples ag_generator("user_network.data", n, m) # generate AG based on user defined network data, n threads and
#' m initial nodes are set. Note n<=m
ag_generator <- function(filename.str=system.file("extdata","example.data",package="attackgraph"),
                         numThreads=1, initQSize=1,
                         so.str=system.file("lib","app.so",package="attackgraph")){
  # CUDA control parameters (only useful on parallel version)
  numThreads <- as.integer(numThreads)
  initQSize <- as.integer(initQSize)
  filename <- utf8ToInt(filename.str)
  fNameLength <- length(filename)

  # predefine data structures to store the resulting graph
  edges <- rep(as.integer(0), 7*10000000)
  nE <- as.integer(0)
  nodes <- rep(as.integer(0), 3*1000000)
  nN <- as.integer(0)
  print(so.str)


  # load the shared object and generate the AG
  dyn.load(so.str) # to be "app.so"
  if(is.loaded("cuGenFunc")){
    print("R: shared object loading successful!")
    print("R: call the .C function to invoke AG generator function!")
    print("!!")
    res <- .C("cuGenFunc", c(numThreads, initQSize),
              filename, fNameLength, edges, nE, nodes, nN, PACKAGE="app")
    print("")
    print("R: Done !!!")
  }else{
    print("R: shared object loading failed !!!")
  }

  nE <- res[[5]]
  print(paste("R: the number of edges in the AG is", nE))
  edges <- res[[4]][1:(nE*7)]
  mtx.edges <- matrix(edges, ncol=7, byrow=T)
  mtx.edges <- mtx.edges[,1:5]
  colnames(mtx.edges) <- c("edge_id", "from_node", "to_node", "exploit_id", "asset_id")
  if(nE<=50){
    mtx.edges
  }else{
    mtx.edges[1:50,]
  }

  nN <- res[[7]]
  print(paste("R: The number of nodes in the AG is", nN))
  nodes <- res[[6]][1:(nN*3)]
  mtx.nodes <- matrix(nodes, ncol=3, byrow=T)
  colnames(mtx.nodes) <- c("node_id", "num_qualities", "num_topologies")
  if(nN<=50){
    mtx.nodes
  }else{
    mtx.nodes[1:50,]
  }

  if(nN<=50){
    df.g4 <- data.frame(mtx.edges[, c("from_node", "to_node")])
    g4 <- igraph::graph_from_data_frame(df.g4, directed=T)
    layout4 <- igraph::layout_as_tree(g4)
    plot(g4, edge.label=paste("(e", mtx.edges[,"exploit_id"], ",a", mtx.edges[, "asset_id"], ")", sep=""),
         vertex.label.cex=1.5, edge.label.cex=0.8,
         layout=layout4, main=paste("Attack Graph with", nN, "nodes and", nE, "edges)"), main.cex=1
    )
  }
  return(list(node.matrix=mtx.nodes, edge.matrix=mtx.edges, nNodes=nN, nEdges=nE))
}

