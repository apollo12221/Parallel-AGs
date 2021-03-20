# R code to interface with the OpenMP-based attack graph generator
# author: Ming Li
# 3/18/2021

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
#' @examples ag_generator() # all arguments on default to generate AG for a built-in example target network
#'
#' @examples ag_generator(create_network(5), 1, 1) # create a target network with 5 vulnerable hosts and generate the AG
#' with 1 thread and 1 initial node.
#'
#' @examples ag_generator("user_network.data", n, m) # generate AG based on user defined network data, n threads and
#' m initial nodes are set. Note n<=m
#' @export
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


#' display an example that describes a target network
#'
#' This function loads a built-in data file from the package and describes an example target network.
#' Please follow its format to describe your own target network and feed the data file as the input to
#' the ag_generator() function
#'
#' @details The example target network is described by 6 components. The list of assets describes all the
#' devices in the network. The list of qualities describes the configuration information of each device. The
#' list of topologies describes the interconnections between assets. The list of exploits describes each
#' vulnerability name and its class (either local/1 or remote/2). The list of exploit preconditions describes
#' the requirements of each vulnerability to be successfully exploited. The list of exploit postconditions
#' describes the consequences of each vulnerablity exploitation.
#' @examples format_ref() # display the content of the data file
#' @export
format_ref <- function(){
  f1 <- readLines(system.file("extdata","example.data",package="attackgraph"))
  for(i in f1){
    message(i)
  }
}

#' create a data file for a target network.
#'
#' This function creates a data file for a target network. The target network follows a fixed pattern
#' to grow in size, and the number of vulnerable hosts (attacker not included) can be set through an argument.
#'
#' @param nv The number of vulnerable hosts, default 5
#' @return The path name of the generated data file
#' @details This function creates target networks described by their data files for testing the attack graph
#' generator. The data file can be directly read by the ag_generator() function. Pass the returned path name to
#' the first argument of the ag_generator() function and the corresponding AG can be generated. Note that the
#' number of vulnerable hosts determines the execution time. While it is safe to set a small nv between 3 and
#' 100, larger values are not recommended.
#' @examples filename <- create_network(5) # create the data file for a target network with 5 vulnerable hosts
#' @export
create_network <- function(nv=5){
  d = nv
  n = (1+d)*d/2+1
  g2.df = data.frame(from.node=c(0), to.node=c(0))

  edge.cnt = 1
  for(i in 1:d){
    start.id = i*(i-1)/2
    if(i<d){
      for(j in 1:i){
        g2.df[edge.cnt,1]=start.id+j
        g2.df[edge.cnt,2]=start.id+j+i
        edge.cnt = edge.cnt + 1
        g2.df[edge.cnt,1]=start.id+j
        g2.df[edge.cnt,2]=start.id+j+i+1
        edge.cnt = edge.cnt + 1
      }
    }else{
      for(j in 1:i){
        g2.df[edge.cnt,1]=start.id+j
        g2.df[edge.cnt,2]=n
        edge.cnt = edge.cnt + 1
      }
    }
  }

  nE <- nrow(g2.df)
  nN <- max(g2.df[,2])

  edge_i = 1
  while(edge_i<=nE){
    row.idx = (1:nE)[g2.df[,1]==g2.df[edge_i,1]]
    od <- order(g2.df[row.idx,2])
    g2.df[row.idx,] = g2.df[row.idx,][od,]
    edge_i = edge_i + length(row.idx)
  }

  colnames(g2.df) <- c("from_node", "to_node")
  #g2 <- igraph::graph_from_data_frame(g2.df, directed=T)
  #layout2 <- igraph::layout_as_tree(g2, root=1)

  nid <- nN
  max.depth <- 0
  while(nid!=1){
    nid <- g2.df[g2.df[,2]==nid,1][1]
    max.depth <- max.depth + 1
  }
  message("graph basic information:")
  message(paste("Number of nodes is", nN))
  message(paste("Number of edges is", nE))
  message(paste("Depth of the graph is", max.depth))

  g2.df[,3] <- 0 # edge status column, indicating if an edge has been traversed
  g2.df[,4] <- 0 # edge label
  parent.vec <- rep(-1, max(g2.df[,2]))
  ecnt <- 1
  current_node <- 1
  parent.vec[1] <- 0
  node.up <- matrix(0,nrow=nN,ncol=max.depth)
  node.down <- matrix(0, nrow=nN, ncol=max.depth)
  node.inbound <- matrix(0,nrow=nN, ncol=max.depth)
  violation <- F
  violation.current.node <- 0
  violation.child.node <- 0


  while(T){ #until every edge is labeled as traversed
    if(current_node==0){
      if(sum(g2.df[,3]==0)==0) break
      current_node=1
    }
    if(!violation){ #no violation, then traversal continues
      current_node_rows <- which(g2.df[,1]==current_node) #the rows of the current node as the source in the original data frame
      neighbor_cnt <- length(current_node_rows) #number of neighbors of the current node
      neighbor_i <- sum(g2.df[current_node_rows,3]) #how many neighbors has been accessed from the current node
      if(neighbor_i==neighbor_cnt){#all accessed, then go to parent
        current_node <- parent.vec[current_node]
      }else{#still have neighbor to traverse
        current_edge = current_node_rows[neighbor_i+1]
        child <- g2.df[current_edge,2] #get the neighbor
        child.visited = F
        if(parent.vec[child]!=-1) child.visited = T #check if the neighbor has been visited
        if(!child.visited){#child unvisited, may change current node to to the child node
          node.up[child,] <- node.up[current_node,]
          usable.labels <- (1:max.depth)[(node.up[current_node,]+node.down[current_node,])==0]
          if(length(usable.labels)==0){
            violation=T
            print("Failure: running out of usable labels on unvisited child")
            break
          }
          g2.df[current_edge,3]=1 #current edge has been traversed
          node.down[current_node,usable.labels[1]]=1
          g2.df[current_edge,4]=usable.labels[1]
          node.up[child,usable.labels[1]]=1
          parent.vec[child]=current_node
          current_node=child
        }else{#child visited, no need to change current node
          cmp = (1:max.depth)[node.up[current_node,]!=node.up[child,]]
          if(length(cmp)!=1){#in case the used labels of the current node not included in its child's, back track
            violation=T
            pnode = parent.vec[current_node]
            in.edge = which(g2.df[,1]==pnode & g2.df[,2]==current_node)
            # print(paste("Warning: violation", "parent", pnode, "current", current_node, "label", g2.df[in.edge,4]))
            g2.df[in.edge,3]=0 # reset the visiting status of the most recent inbound edge
            #g2.df[in.edge,4]=0 # reset the label of the most recent inbound edge
            #parent.vec[current_node]=-1
            node.up[current_node,]=node.up[pnode,]
            current_node=pnode
          }else{
            if(is.element(cmp[1],g2.df[current_node_rows,4])){
              violation=T
              print("Failure: too complicated graph to assign labels")
              print(paste("exit with", "parent", parent.vec[current_node], "current", current_node, "child", child,
                          "cmp[1]",cmp[1]))
              print("node down vector of the current node")
              print(node.down[current_node,])
              print("node up vector of the current node")
              print(node.up[current_node,])
              break
            }else{
              node.down[current_node, cmp[1]]=1
              g2.df[current_edge, 3]=1
              g2.df[current_edge, 4]=cmp[1]
            }
          }
        }
      }
    }else{ # in case of violation, the current node must have unvisited neighbors !
      current_node_rows <- which(g2.df[,1]==current_node) #the rows of the current node as the source in the original data frame
      neighbor_cnt <- length(current_node_rows) #number of neighbors of the current node
      neighbor_i <- sum(g2.df[current_node_rows,3]) #how many neighbors has been accessed from the current node
      current_edge = current_node_rows[neighbor_i+1]
      child <- g2.df[current_edge,2] #get the neighbor
      node.up[child,] <- node.up[current_node,]
      usable.labels <- (1:max.depth)[(node.up[current_node,]+node.down[current_node,])==0]
      if(length(usable.labels)==0){
        violation=T
        print("Failure: needs to backtrack more than one level")
        break
      }
      idx=sample(length(usable.labels),1)
      g2.df[current_edge,3]=1 #current edge has been traversed
      node.down[current_node,usable.labels[idx]]=1
      node.down[current_node,g2.df[current_edge,4]]=0
      g2.df[current_edge,4]=usable.labels[idx]
      node.up[child,usable.labels[idx]]=1
      parent.vec[child]=current_node
      current_node=child
      violation = F
    }
  }


  labels2 <- g2.df[,4]

  if(violation == F){
    frontier <- c(1)
    topo.done <- F
    disc.host <- c()
    topo.mtx <- matrix(0, nrow=max.depth+1, ncol=max.depth+1)
    inbound.devices <- matrix(0, nrow=nN, ncol=max.depth+1)
    inbound.devices[1,1]=1
    device.status <- rep(0, max.depth+1)
    while(length(frontier)>0){
      next.frontier <- c()
      for(i in frontier){
        for(j in g2.df[g2.df[,1]==i,2]){
          if(!is.element(j,next.frontier)){
            next.frontier[length(next.frontier)+1]=j
          }
          edge.id <- which((g2.df[,1]==i)&(g2.df[,2]==j))
          inbound.devices[j, g2.df[g2.df[,2]==j,4]+1]=1
          if(sum(node.up[j,]*topo.mtx[2:(max.depth+1),labels2[edge.id]+1])==0){
            for(k in which(inbound.devices[i,]==1)){
              if(inbound.devices[j,k]!=1){
                topo.mtx[k, labels2[edge.id]+1]=1
              }
            }
          }
        }
      }
      device.status[] <- 0
      frontier <- next.frontier
    }

    fs <- file(paste("user_nw",d,".data",sep=""))
    asset.title = "INSERT INTO asset VALUES"
    nNodes = max.depth + 1
    asset.list = paste("(",0:(nNodes-1),", 'host",0:(nNodes-1),"'),", sep="")
    asset.list[nNodes] = paste("(",nNodes-1,", 'host",nNodes-1,"');", sep="")

    quality.title = "INSERT INTO quality VALUES"
    quality.list = c()
    root.vec = c(1)
    for(i in 1:nNodes){
      if(is.element(i,root.vec)){
        if(i==nNodes){
          quality.list[i] <- paste("(",i-1,", 'root', '=', 'true');",sep="")
        }else{
          quality.list[i] <- paste("(",i-1,", 'root', '=', 'true'),",sep="")
        }
      }else{
        if(i==nNodes){
          quality.list[i] <- paste("(", i-1, ", 'os', '=', 'v", i-1, "');", sep="")
        }else{
          quality.list[i] <- paste("(", i-1, ", 'os', '=', 'v", i-1, "'),", sep="")
        }
      }
    }

    topology.title = "INSERT INTO topology VALUES"
    topology.list = c()
    link.total = sum(topo.mtx)
    tcnt = 1
    for(i in 1:nNodes){
      for(j in 1:nNodes){
        if(topo.mtx[i,j]==1){
          if(tcnt==link.total){
            topology.list[tcnt]=paste("(", i-1, ", ", j-1, ", '->', 'conn', '', '');", sep="")
          }else{
            topology.list[tcnt]=paste("(", i-1, ", ", j-1, ", '->', 'conn', '', ''),", sep="")
          }
          tcnt=tcnt+1
        }
      }
    }

    exploit.title = "INSERT INTO exploit VALUES"
    exploit.list = paste("(", 0:(max.depth-1), ", 'e", 0:(max.depth-1), "', 2),", sep="")
    exploit.list[max.depth] = paste("(", max.depth-1, ", 'e", max.depth-1, "', 2);", sep="")

    precondition.title = "INSERT INTO exploit_precondition VALUES"
    precondition.list=c()
    for(i in 1:max.depth){
      if(i==max.depth){
        precondition.list[(i-1)*3+1]=paste("(", 3*(i-1), ", ", (i-1), ", 0, 0, 0, 'root', 'true', '=', '(null)'),",  sep="")
        precondition.list[(i-1)*3+2]=paste("(", 3*(i-1)+1, ", ", (i-1), ", 0, 1, 0, 'os', 'v", i, "', '=', '(null)')," , sep="")
        precondition.list[(i-1)*3+3]=paste("(", 3*(i-1)+2, ", ", (i-1), ", 1, 0, 1, 'conn', '', '', '->');", sep="")
      }else{
        precondition.list[(i-1)*3+1]=paste("(", 3*(i-1), ", ", (i-1), ", 0, 0, 0, 'root', 'true', '=', '(null)'),",  sep="")
        precondition.list[(i-1)*3+2]=paste("(", 3*(i-1)+1, ", ", (i-1), ", 0, 1, 0, 'os', 'v", i, "', '=', '(null)')," , sep="")
        precondition.list[(i-1)*3+3]=paste("(", 3*(i-1)+2, ", ", (i-1), ", 1, 0, 1, 'conn', '', '', '->'),", sep="")
      }
    }

    postcondition.title = "INSERT INTO exploit_postcondition VALUES"
    postcondition.list=c()
    for(i in 1:max.depth){
      if(i==max.depth){
        postcondition.list[i]=paste("(", i-1, ", ", i-1, ", 0, 1, 0, 'root', 'true', '=', '(null)', 'insert');", sep="")
      }else{
        postcondition.list[i]=paste("(", i-1, ", ", i-1, ", 0, 1, 0, 'root', 'true', '=', '(null)', 'insert'),", sep="")
      }
    }

    writeLines(c(asset.title, asset.list, quality.title, quality.list, topology.title, topology.list, exploit.title,
                 exploit.list, precondition.title, precondition.list, postcondition.title, postcondition.list), fs)

    close(fs)
    message("target network created")
  }else{
    message("unable to create target network")
    fs <- file(paste("user_nw",d,".data",sep=""))
    close(fs)
  }
  path = normalizePath(paste("user_nw",d,".data",sep=""))
  return(path)
}

