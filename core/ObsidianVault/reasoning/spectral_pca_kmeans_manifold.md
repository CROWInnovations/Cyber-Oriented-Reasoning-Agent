---
title: spectral_pca_kmeans_manifold
category: reasoning
engine: spectral_pca_kmeans
summary: Engine 20 PCA (74.9% var) & K-Means++ Cluster `C0_LOCAL_LAN_DISCOVERY` (Chokepoint: `NIC:<PRIMARY_NIC>`)
tags: [reasoning, spectral_pca_kmeans, pca, kmeans, spectral-laplacian, manifold, clustering]
updated: 2026-10-31 20:12:11
---
# spectral_pca_kmeans_manifold

> **Engine:** `spectral_pca_kmeans` | **Summary:** Engine 20 PCA (74.9% var) & K-Means++ Cluster `C0_LOCAL_LAN_DISCOVERY` (Chokepoint: `NIC:<PRIMARY_NIC>`)  
> **Backlink:** [[00_MEMORY_INDEX]] | **Updated:** `2026-10-31 20:12:11`

### Engine 20: SVD Principal Component Analysis (PCA), K-Means++ & Spectral Laplacian
- **Active K-Means++ Cluster Assignment**: **`C0_LOCAL_LAN_DISCOVERY`** — *Unmapped Local LAN & Neighbor Discovery Phase* (Silhouette = `0.649`)
- **Cluster Strategic Focus**: Enumerate local interfaces/CIDRs, routing table, and active L2 ARP neighbors first.
- **SVD PCA Cumulative Variance (Top 3 PCs)**: **`74.9%`** across `25` manifold states
  - **PC1 (`33.2%` var)**: Driven by `f3_target_in_local_l2` (+0.60), `f4_cross_subnet_l3_hop` (-0.43), `f1_default_or_static_route` (+0.35)
  - **PC2 (`25.7%` var)**: Driven by `f7_tcp_conn_refused_exit7` (-0.53), `f8_open_tcp_port_verified` (+0.50), `f9_oob_serial_attached` (-0.50)
  - **Low-Variance Noise Features (Ignore/Deprioritize)**: `f0_local_iface_cidr, f11_l7_goal_verified, f2_l2_arp_reachable`
- **Manifold Outlier / Anomaly Check**: `MANIFOLD_INLIER` (Mahalanobis $D_M = 0.540$, PCA Residual = `0.612`)
- **Spectral Graph Laplacian ($\lambda_2 = 0.382$)**: Chokepoint Cut-Vertices = `['NIC:<PRIMARY_NIC>', 'Node:<TARGET_IP>', 'Subnet:<LOCAL_SUBNET>']`
