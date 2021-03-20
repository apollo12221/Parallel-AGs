#' create a target network for the ag_generator() function based on user-defined directed acyclic graph (DAG)
#'
#' This function creates a target network from a user-defined directed acyclic graph and the data file of the
#' target network can be used as input to the ag_generator() function.
#'
#' @param dag.filename The file name of the user DAG, which should provide an edge list
#' @param nw.filename The file name for the target network. Default "user_nw.data".
#' @details This function takes a DAG as input, labels its edges with asset/exploit ids. If the labeling process
#' is successful, the labeled DAG is then converted to a target network described in a data file, which can be
#' used as the input of the ag_generator() function. If the labeling process fails, no data file will be created.
#' Note that the adjacency matrix of the input DAG should be an upper triangle matrix with all its diagonal
#' entry being 0. Moreover, there must be a path from node 1 to all other nodes.
#' @examples dag2ag("mydag.txt", "my_nw.data") # read a DAG's edge list from "mydag.txt" and convert it to a
#' target network described by the data file "my_nw.data"
#' @export
dag2ag <- function(dag.filename, nw.filename="user_nw.data"){
  g2.df <- read.table(dag.filename)
  g2.df <- g2.df[,1:2] #only use the first two columns
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
  g2 <- igraph::graph_from_data_frame(g2.df, directed=T)
  layout2 <- igraph::layout_as_tree(g2, root=1)

  nid <- nN
  max.depth <- 0
  while(nid!=1){
    nid <- g2.df[g2.df[,2]==nid,1][1]
    max.depth <- max.depth + 1
  }

  violation <- F

  in.degs <- rep(0, nN)
  out.degs <- rep(0, nN)
  for(i in 1:nN){
    in.degs[i] <- sum(g2.df[,2]==i)
    out.degs[i] <- sum(g2.df[,1]==i)
  }
  if(sum(in.degs+out.degs>max.depth)>0){
    violation = T
  }

  if(!violation){
    print("graph basic information:")
    print(paste("Number of nodes is", nN))
    print(paste("Number of edges is", nE))
    print(paste("Depth of the graph is", max.depth))
    g2.df[,3] <- 0 # edge status column, indicating if an edge has been traversed
    g2.df[,4] <- 0 # edge label
    parent.vec <- rep(-1, max(g2.df[,2]))
    ecnt <- 1
    current_node <- 1
    parent.vec[1] <- 0
    node.up <- matrix(0,nrow=nN,ncol=max.depth)
    node.down <- matrix(0, nrow=nN, ncol=max.depth)
    node.inbound <- matrix(0,nrow=nN, ncol=max.depth)

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
            #idx=sample(length(usable.labels),1)
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
              #print(paste("Warning: violation", "parent", pnode, "current", current_node, "label", g2.df[in.edge,4]))
              g2.df[in.edge,3]=0 # reset the visiting status of the most recent inbound edge
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

    if(nN<50){
      par(mfrow=c(1,2))
      plot(g2, layout=layout2, vertex.size=20, edge.width=1.0, edge.color="black", vertex.label.cex=1.0,
           edge.arrow.size=0.5, main="Original DAG")
      plot(g2, layout=layout2, edge.label=paste("a",g2.df[,4]), edge.label.cex=3,
           vertex.size=20, vertex.label.cex=3, edge.width=1.0, edge.color="black", edge.arrow.size=0.5,
           main="DAG with edge labeld by asset ids")
      par(mfrow=c(1,1))
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

      ## create the input for AG generator now
      fs <- file(nw.filename)
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
      message(paste("The input DAG has been successfully converted to a target network, please find the data file",
              nw.filename, "in the current R working directory"))
    }else{
      message("The input DAG cannot be converted to a target network !!")
    }
  }else{
    message("The input DAG cannot be converted to a target network !!")
  }
}
