#ifndef PACKET_BTREE_H
#define PACKET_BTREE_H

#include "Packet.h"
#include <vector>
#include <memory>
#include <algorithm>

// B-tree implementation for efficient time-range queries
template<int ORDER = 5>
class PacketBTree {
private:
    struct Node {
        bool isLeaf;
        std::vector<long long> keys;  // timestamps in milliseconds
        std::vector<std::shared_ptr<Packet>> packets;
        std::vector<std::shared_ptr<Node>> children;

        Node(bool leaf = true) : isLeaf(leaf) {}
    };

    std::shared_ptr<Node> root;
    static const int MIN_DEGREE = ORDER;

    // Split a full child node
    void splitChild(std::shared_ptr<Node> parent, int index) {
        auto fullChild = parent->children[index];
        auto newChild = std::make_shared<Node>(fullChild->isLeaf);

        int midIndex = MIN_DEGREE - 1;

        // Move the second half of keys and packets to new node
        newChild->keys.assign(
            fullChild->keys.begin() + midIndex + 1,
            fullChild->keys.end()
        );
        newChild->packets.assign(
            fullChild->packets.begin() + midIndex + 1,
            fullChild->packets.end()
        );

        // If not a leaf, move children as well
        if (!fullChild->isLeaf) {
            newChild->children.assign(
                fullChild->children.begin() + midIndex + 1,
                fullChild->children.end()
            );
            fullChild->children.erase(
                fullChild->children.begin() + midIndex + 1,
                fullChild->children.end()
            );
        }

        // Move middle key to parent
        parent->keys.insert(parent->keys.begin() + index, fullChild->keys[midIndex]);
        parent->packets.insert(parent->packets.begin() + index, fullChild->packets[midIndex]);
        parent->children.insert(parent->children.begin() + index + 1, newChild);

        // Remove moved elements from original child
        fullChild->keys.erase(
            fullChild->keys.begin() + midIndex,
            fullChild->keys.end()
        );
        fullChild->packets.erase(
            fullChild->packets.begin() + midIndex,
            fullChild->packets.end()
        );
    }

    // Insert into a non-full node
    void insertNonFull(std::shared_ptr<Node> node, long long key, std::shared_ptr<Packet> packet) {
        int i = node->keys.size() - 1;

        if (node->isLeaf) {
            // Insert into sorted position
            node->keys.push_back(0);
            node->packets.push_back(nullptr);
            
            while (i >= 0 && key < node->keys[i]) {
                node->keys[i + 1] = node->keys[i];
                node->packets[i + 1] = node->packets[i];
                i--;
            }
            
            node->keys[i + 1] = key;
            node->packets[i + 1] = packet;
        } else {
            // Find child to insert into
            while (i >= 0 && key < node->keys[i]) {
                i--;
            }
            i++;

            // Split child if full
            if (node->children[i]->keys.size() == 2 * MIN_DEGREE - 1) {
                splitChild(node, i);
                if (key > node->keys[i]) {
                    i++;
                }
            }
            insertNonFull(node->children[i], key, packet);
        }
    }

    // Range query helper
    void rangeQueryHelper(std::shared_ptr<Node> node, long long startTime, long long endTime,
                         std::vector<std::shared_ptr<Packet>>& results) const {
        if (!node) return;

        int i = 0;
        int n = node->keys.size();

        // Traverse through keys
        for (i = 0; i < n; i++) {
            // If not a leaf, recurse on child
            if (!node->isLeaf) {
                rangeQueryHelper(node->children[i], startTime, endTime, results);
            }

            // If key is in range, add packet
            if (node->keys[i] >= startTime && node->keys[i] <= endTime) {
                results.push_back(node->packets[i]);
            }

            // If we've passed the end time, stop
            if (node->keys[i] > endTime) {
                return;
            }
        }

        // Check last child if not a leaf
        if (!node->isLeaf) {
            rangeQueryHelper(node->children[i], startTime, endTime, results);
        }
    }

    // Collect all packets (in-order traversal)
    void collectAll(std::shared_ptr<Node> node, std::vector<std::shared_ptr<Packet>>& results) const {
        if (!node) return;

        int n = node->keys.size();
        for (int i = 0; i < n; i++) {
            if (!node->isLeaf) {
                collectAll(node->children[i], results);
            }
            results.push_back(node->packets[i]);
        }
        
        if (!node->isLeaf) {
            collectAll(node->children[n], results);
        }
    }

public:
    PacketBTree() {
        root = std::make_shared<Node>(true);
    }

    // Insert a packet
    void insert(std::shared_ptr<Packet> packet) {
        long long key = packet->getTimestampMs();

        // If root is full, split it
        if (root->keys.size() == 2 * MIN_DEGREE - 1) {
            auto newRoot = std::make_shared<Node>(false);
            newRoot->children.push_back(root);
            splitChild(newRoot, 0);
            root = newRoot;
        }

        insertNonFull(root, key, packet);
    }

    // Range query: find all packets within a time range
    std::vector<std::shared_ptr<Packet>> rangeQuery(long long startTime, long long endTime) const {
        std::vector<std::shared_ptr<Packet>> results;
        rangeQueryHelper(root, startTime, endTime, results);
        return results;
    }

    // Get all packets sorted by timestamp
    std::vector<std::shared_ptr<Packet>> getAllSorted() const {
        std::vector<std::shared_ptr<Packet>> results;
        collectAll(root, results);
        return results;
    }

    // Check if tree is empty
    bool empty() const {
        return root->keys.empty();
    }

    // Get count of packets
    size_t size() const {
        std::vector<std::shared_ptr<Packet>> all;
        collectAll(root, all);
        return all.size();
    }
};

#endif // PACKET_BTREE_H
