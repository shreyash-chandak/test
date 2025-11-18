# Google Docs Watch Out


## Docs++: A Concurrent Distributed File System

We loved working on this project and spent a lot of time fine-tuning and adding cool features to it (along with the bonus). To check out a full list of these features, simply type `help` inside a client terminal session :D

[Methodology](#protocols-and-implementation-logic)

[Protocols for Data Flow](#data-flow-and-protocol-behavior)

[Atomic Recovery and Persistent Metadata Logging](#persistence-and-atomic-recovery)

[Fault Tolerance](#fault-tolerance-and-high-availability)

[Additional Features](#additional-implementations)


[Provided Resources Used](https://www.youtube.com/watch?v=dQw4w9WgXcQ)


---

## Build and Run Instructions

The project includes a Makefile for easy compilation.

#### 1. Clone and Build

```bash
git clone <repo-url>
cd course-project-traphandlers/
make
```


#### 2. Run Name Server

```bash
./bin/nm
```


#### 3. Run Storage Server

```bash
# Usage: ./bin/ss <data_dir> <public_ip> <nm_ip> <nm_port> <client_port>
./bin/ss ./storage1 127.0.0.1 127.0.0.1 8080 5000
```


#### 4. Run Client

```bash
# Usage: ./bin/client <public_ip> <nm_port>
./bin/client 127.0.0.1 8080
```

---

## Protocols and Implementation Logic

### 1. Custom Binary Protocol

All communication between the Client, Name Server (NM), and Storage Servers (SS) occurs through a custom fixed-header binary protocol.

**Serialization**  
Messages are composed of `MsgHeader` and `MsgPayload` structures. All integer fields are converted to network byte order (`htons`, `htonl`) and reversed on receipt, ensuring cross-platform compatibility.

**Reliable Transport**  
Custom `send_all` and `recv_all` functions guarantee full transmission of packets, avoiding partial `send` and `recv` issues that arise when using raw TCP.

**Checksums**  
Payloads include a simple additive checksum to detect data corruption during transit.

---
### 2. Efficient Search via LRU Caching

To optimize file lookup times and reduce overhead on the global hashmap, the Name Server implements a thread-safe Least Recently Used (LRU) Cache.

Frequently accessed file metadata (permissions, size, location) is cached in memory.

The cache handles concurrent access via fine-grained mutex locking, ensuring O(1) access time for hot files.

---

### 3. High-Concurrency Two-Level Locking (Storage Server)

A core design goal is to support high concurrency. Instead of locking an entire file during every operation, each Storage Server uses a two-level locking scheme.

#### Level 1: O(1) File-Level Access

A global thread-safe hashmap, `file_lock_map`, provides constant-time access from a filename to its `FileLockInfo` structure. This structure holds all concurrency primitives for that file.

#### Level 2: Fine-Grained and Coarse-Grained Locking

Each `FileLockInfo` contains:

- `pthread_rwlock_t content_rw_lock`
- `ts_hashmap_t* sentence_locks`

#### How It Works

- `WRITE_START` acquires only the sentence-level mutex.  
- READ acquires the file-level read lock but does not block other sentence writes.  
- `ETIRW` escalates to a full write lock for atomic commit.

---

### 4. Stateful Write Sessions

The Storage Server maintains a `WriteSession` structure for each active write.

**Operation Buffering**  
Incoming `WRITE_DATA` operations are stored as a LIFO list.

**Correct Commit Ordering**  
During commit, operations are applied in reverse linked-list order for correct FIFO semantics.

**Graceful Disconnect Recovery**  
If a client disconnects, the server releases the sentence mutex and prevents deadlock.

---

## Data Flow and Protocol Behavior

### Direct Access (Read / Stream / Write)

1. Client sends request to NM.  
2. NM validates and returns SS location.  
3. Client connects directly to SS.  
4. SS performs the operation.

### Centralized Control (Create / Delete)

1. Client sends request to NM.  
2. NM forwards to SS.  
3. SS processes and acknowledges.  
4. NM updates metadata and confirms.

### Coordinated Commit (`ETIRW`)

Commit is handled directly by SS, followed by asynchronous metadata updates to NM.

---

## Persistence and Atomic Recovery

### Write-Ahead Logging (WAL)

The Name Server maintains a persistent metadata.log and users.log. Every critical operation (User Registration, File Creation, Access Change, Write Commit) is appended to the log before being acknowledged. This allows the Name Server to reconstruct the entire system state from zero in the event of a crash.

### Pre-existing Files = Publicly Readable

To handle files that exist on the Storage Server disks before being formally created (e.g., pre-existing data), we implemented a flexible public access feature:

- Such a file is given the ownership of `unregistered` for RW, as no client created it.

- All clients are given read access to such files but not write access. (Our protocol)

- As a sidenote, the authentication logic prohibits any _real_ client from registering with the username 'unregistered' or 'all', ensuring this mechanism is secure and reserved for system use.

### Startup Persistence

On boot, the server scans the directory for files and initializes lock structures. Any files 

### Atomic Undo/Redo via Three-Way Swap

Undo/redo functionality uses a consistent, atomic rename sequence `file.txt` ↔ `file.txt.bak` ↔ `file.txt.undoing` to ensure state is never lost, even if a crash occurs mid-operation.

---

## Fault Tolerance and High Availability

### Async Replication
To ensure data durability, the system implements an asynchronous replication strategy. Every file creation is duplicated across a Primary and a Secondary Storage Server. Write operations committed to the Primary are asynchronously propagated to the Secondary to minimize client latency while maintaining redundancy.

### Automatic Failover & Recovery
The Name Server actively monitors Storage Server health.

- **Failure Detection:** If a Primary SS disconnects, the Name Server detects the socket closure and immediately promotes the Secondary SS to Primary, ensuring uninterrupted access for clients.

- **Recovery:** When a Storage Server rejoins the network, it syncs its file list with the Name Server, which automatically reintegrates the orphaned files into the system state.

---

## Checkpoints

- `checkpoint <file> <tag>` creates a versioned copy.  
- `revert <file> <tag>` restores from a checkpoint.  
- `viewcheckpoint <file> <tag>` streams the checkpoint file.  
- `listcheckpoints <file>` lists all checkpoint versions.


## Request Access

Clients can also request file access from the owner who can either approve or deny the request.

---

# Additional Implementations

## EXEC Protection

When testing across devices, out of fear that our friends could `rm -rf /` my entire custom Arch setup, we made sure `EXEC` commands run under `ulimit` restrictions and check for malicious commands before running on the Name Server.

## Name Server Adopts Orphaned Files

If name server dies mid session, the file metadata is rebuilt using WAL or Write-Ahead-Logic from the `metadata.log`. 

Moreover it will be automatically repopulated with all file locations and metadata as soon as the Storage Servers reconnect and tell it what they have.

## Password Authentication
Along with only the username to track sessions, we added a persistent password-based authentication system.

To generate a new account on Docs++, simply create a new unique username and give it a password. Your account info will be stored persistently for future sessions.

## REDO Feature
Full redo functionality mirroring the undo mechanism.

## clear Command
A simple client UI enhancement for peace of mind.

## Colourful Terminal :D

The client session prompt is displayed as `username@Docs++>` in bright yellow and pink. The `help` menu uses a colorful ANSI-aligned layout for maximum readability.

---

### Authors:
- [`Shreyash Chandak`](https://github.com/shreyash-chandak)
- [`Pranav Swarup Kumar`](https://github.com/Pranav-Swarup)

---
