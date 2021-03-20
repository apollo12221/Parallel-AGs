# R code to analyze Attack Graphs
# author: Ming Li
# 3/18/2021

ev.assgn <- function(A, vec, r.min=length(vec)){
  nNodes <- nrow(A)
  node.order <- order(order(vec, decreasing=T))
  node.enable <- node.order<=r.min
  evalues <- rep(0, sum(A))
  v.mtx <- matrix(0, nrow=nNodes, ncol=nNodes)
  for(i in 1:nNodes){
    if(node.enable[i]){
      num.in.edge = sum(A[,i])
      for(j in 1:nNodes){
        if(A[j,i]==1){
          v.mtx[j,i] = v.mtx[j,i] + vec[i]/num.in.edge
        }
      }
    }
  }
  ecnt <- 1
  for(i in 1:nNodes){
    for(j in 1:nNodes){
      if(A[i,j]==1){
        evalues[ecnt] <- v.mtx[i,j]
        ecnt <- ecnt + 1
      }
    }
  }
  return(evalues)
}

ex.ranking <- function(ed.values, ed.labels){
  num.ex <- max(ed.labels)+1
  if(min(ed.labels)==1){
    num.ex <- max(ed.labels)
  }
  ex.values <- rep(0, num.ex)
  for(i in 1:num.ex){
    if(min(ed.labels)==0){
      ex.values[i] <- sum(ed.values[ed.labels==i-1])
    }else{
      ex.values[i] <- sum(ed.values[ed.labels==i])
    }
  }
  return(ex.values)
}


#' Analyze an Attack Graph data with adapted PageRank Centrality (APC)
#'
#' This function computes adapted PageRank centrality (APC) for given Attack Graphs
#'
#' @param edge.matrix The Matrix of Attack Graph edges provided by the output of ag_generator() function.
#' @param data.matrix User-defined data matrix. The number of rows must equal to the number of Attack Graph nodes,
#' the number of columns equals to the number features.
#' @param data.weight.vector Add non-negative weights on the features(columns) of the data.matrix. The total
#' weight must be 1. The default vector assigns equal weight to each feature
#' @param alpha The coefficient to balance Attack Graph topology (edge.matrix) and user-defined data. Range
#' between 0 and 1, default 0.5.
#' @return A list of exploit APC values, asset APC values, node APC values and node APC ranks
#' @details This function computes the APC values for every Attack Graph nodes and ranks them in a descending order.
#' Each node's APC value is also evenly distributed to its inbound edges and as such each edge has some partial
#' APC value. As Attack Graph edges are labeled with exploit ids or asset ids, by computing the total APC of edges
#' labeled by the same exploit/asset, an APC value is computed for each exploit/asset, based on which an order to
#' patch the exploits or defend the assets can be obtained. Therefore, in addition to node APC values and ranks,
#' this function also returns exploit APC values, asset APC values for user's subsequent analysis.
#' @examples APC(user_attack_graph$edge.matrix, matrix(1/N, nrow=N, ncol=1)) # Reduce to PageRank of Attack Graph
#' nodes, and N=user_attack_graph$nNodes
#' @export
APC <- function(edge.matrix, data.matrix, data.weight.vector=rep(1/ncol(data.matrix), ncol(data.matrix)),
                alpha=0.5){
  # step 1: original data and preprocessing
  df1 <- edge.matrix[,2:5]
  mtx.dim <- max(df1[, 1:2])
  mtx1 <- matrix(0, nrow=mtx.dim, ncol=mtx.dim)
  for(i in 1:nrow(df1)){
    mtx1[df1[i,1], df1[i,2]]=1
  }
  g1 <- igraph::graph_from_adjacency_matrix(mtx1, "directed")
  layout2 <- igraph::layout_as_tree(g1)
  deg1 <- rowSums(mtx1)
  nN <- nrow(mtx1)
  nE <- nrow(df1)
  # step 2: adjacency matrix and data matrix
  # deg1 <- degree(g1, mode="out")
  A_star <- t(mtx1/deg1)
  A_star[,deg1==0] <- 0.0
  for(i in 1:nN){ # properly process nodes without outgoing edges (leaf nodes)
    if(deg1[i]==0) A_star[i,i]=1.0
  }
  D <- data.matrix
  # step 3: weight vector
  v0 <- matrix(data.weight.vector, nrow=ncol(D), ncol=1)
  # step 4: weighted data vector
  v <- D%*%v0
  # step 5: normalized data vector
  v_star <- v/sum(v)
  # step 6: build V matrix
  V <- v_star%*%matrix(1,nrow=1,ncol=nN)
  # step 7 build APA matrix
  M.APA <- alpha*A_star + (1-alpha)*V
  # step 8 solve for dominant eigenvector of the APA matrix, which will be the APA vector
  # eig <- eigen(M.APA)
  # eig$values
  # APA.vec1 <- Re(eig$vectors[,1])
  # APA.vec1 <- APA.vec1/sum(APA.vec1)
  APA.vec <- c(solve(M.APA[1:(nN-1),1:(nN-1)]-diag(1, nN-1), -1*M.APA[1:(nN-1),nN]), 1)
  APA.vec <- APA.vec/sum(APA.vec)

  #APA.rank <- order(order(APA.vec,decreasing=T))

  ex.counts <- rep(0, max(df1[,3])+1)
  for(i in 0:max(df1[,3])){
    ex.counts[i+1] <- sum(df1[,3]==i)
  }

  asset.counts <- rep(0, max(df1[,4]))
  for(i in 1:max(df1[,4])){
    asset.counts[i] <- sum(df1[,4]==i)
  }

  ex.values <- ex.ranking(ev.assgn(mtx1, APA.vec), df1[,3])#/ex.counts
  names(ex.values) <- paste("ex",(0:max(df1[,3])),sep="")

  asset.values <- ex.ranking(ev.assgn(mtx1, APA.vec), df1[,4])#/asset.counts
  names(asset.values) <- paste("a",(1:max(df1[,4])),sep="")

  if(nN<=50){
    par(mfrow=c(1,2))
    plot(g1, main="original AG", layout=layout2,
         vertex.label=paste("s",1:nN, sep=""),
         edge.label = paste("a", df1[,4], sep=""),
         edge.arrow.size=0.2)
    plot(g1, main="APC values", layout=layout2,
         vertex.label=round(APA.vec, 2),
         edge.label=paste("e", df1[,3], sep=""),
         edge.arrow.size=0.2)
    par(mfrow=c(1,1))
  }
  return(list(ex.values=ex.values, asset.values=asset.values, node.values=APA.vec))
}




#' Analyze an Attack Graph data with edge kpath entrality (EKPC)
#'
#' This function computes edge kpath centrality (EKPC) for given Attack Graphs
#'
#' @param k.value The length k of the paths being counted for each edge
#' @param edge.matrix The Matrix of Attack Graph edges provided by the output of ag_generator() function.
#' @return A list of exploit EKPC values, asset EKPC values, edge EKPC values
#' @details This function computes the edge kpath centrality for all the edges in a given Attack Graph. The total
#' kpath for each exploit/asset is also computed by accumulating the kpath of edges labeled with the same
#' exploit/asset id.
#' @examples EKPC(2, user_attack_graph$edge.matrix) # compute 2-path values for a user Attack Graph
#' @export
EKPC <- function(k.value, edge.matrix){
  # load the data first
  df3 <- edge.matrix[, 2:5]
  mtx.dim <- max(df3[, 1:2])
  mtx3 <- matrix(0, nrow=mtx.dim, ncol=mtx.dim)
  for(i in 1:nrow(df3)){
    mtx3[df3[i,1], df3[i,2]]=1
  }
  nE3 <- nrow(df3)
  nN3 <- nrow(mtx3)
  # for(i in 1:nN3){
  #   if(is.element(i,df3[,1])){
  #     od <- order(df3[,2][df3[,1]==i])
  #     df3[df3[,1]==i,] = df3[df3[,1]==i,][od,]
  #   }
  # }
  g3 <- igraph::graph_from_adjacency_matrix(mtx3, "directed")
  layout3 <- igraph::layout_as_tree(g3)

  # prepare the power of matrix
  mtx.pwr <- list()
  mtx.pwr[[1]] <- mtx3
  for(i in 2:k.value){
    mtx.pwr[[i]]=mtx.pwr[[i-1]]%*%mtx3
  }
  # find the number of k-paths from each node
  kpath.cnt <- rowSums(mtx.pwr[[k.value]])
  # identify the nodes that have at least one k-path
  kpath.exist <- (1:nN3)[kpath.cnt>0]
  # keep the kpath centrality for each edge
  edge.kpath <- rep(0, nE3)
  edge.cnt <- 1
  # The loop to find kpath edge centrality
  for(m in 1:nN3){# loop over rows
    for(i in 1:nN3){# loop over columns
      if(mtx3[m,i]==1){# find an edge
        node.vec <- rep(0, nN3)
        for(j in 1:k.value){
          if(j==1){
            node.vec[m] <- node.vec[m] + sum(mtx.pwr[[k.value-1]][i,])
          }else if(j==k.value){
            node.vec <- node.vec + mtx.pwr[[k.value-1]][,m]
          }else{
            node.vec <- node.vec + rowSums(matrix(mtx.pwr[[j-1]][,m], nrow=nN3) %*% matrix(mtx.pwr[[k.value-j]][i,], ncol=nN3))
          }
        }
        edge.kpath[edge.cnt] = sum(node.vec[kpath.exist]/kpath.cnt[kpath.exist])
        edge.cnt = edge.cnt + 1
      }
    }
  }

  # accumulate the edge kpath for each exploit
  ex.total <- rep(0, max(df3[,3])+1)
  for(i in 1:(max(df3[,3])+1)){
    ex.total[i]=sum(edge.kpath[df3[,3]==i-1])
  }
  # accumulate the edge kpath for each asset
  asset.total <- rep(0, max(df3[,4]))
  for(i in 1:max(df3[,4])){
    asset.total[i]=sum(edge.kpath[df3[,4]==i])
  }

  if(nN3<=40){
    par(mfrow=c(1,2))
    plot(g3, main="original AG", layout=layout3,
         vertex.label=paste("s",1:nN3, sep=""),
         edge.label = paste("a", df3[,4], "e", df3[,3], sep=""),
         edge.arrow.size=0.2)
    plot(g3, main="kpath values", layout=layout3,
         vertex.label=paste("s",1:nN3, sep=""),
         edge.label=round(edge.kpath,2),
         edge.arrow.size=0.2)
    par(mfrow=c(1,1))
  }

  return(list(ex.values=ex.total, asset.values=asset.total, edge.values=edge.kpath))
}


