package exectraces

import (
	"sync"
)

type Node struct {
	prefix    []uint64
	leafValue []string

	children []*Node
}

func (n *Node) longestCommonPrefixLen(key []uint64) int {
	var i int
	for ; i < len(n.prefix) && i < len(key) && n.prefix[i] == key[i]; i++ {
	}
	return i
}

func (n *Node) next(key uint64) *Node {
	for _, child := range n.children {
		if child.prefix[0] == key {
			return child
		}
	}
	return nil
}

func (n *Node) insert(key []uint64, value *string) {
	if n.prefix == nil {
		n.prefix = append(n.prefix, key...) // TODO
		n.leafValue = append(n.leafValue, *value)
		return
	}

	var node *Node = n
	var common int

	for {
		common = node.longestCommonPrefixLen(key)
		key = key[common:]
		if common < len(node.prefix) {
			// split this node
			child := new(Node)
			*child = *node
			*node = Node{}
			node.prefix = child.prefix[:common]
			child.prefix = child.prefix[common:]
			node.children = append(node.children, child)
			// insert new node
			if len(key) != 0 {
				child2 := new(Node)
				node.children = append(node.children, child2)
				child2.insert(key, value)
			} else {
				node.leafValue = append(node.leafValue, *value)
			}
			return
		}

		if len(key) == 0 {
			node.leafValue = append(node.leafValue, *value)
			return
		}

		child := node.next(key[0])
		if child == nil {
			child2 := new(Node)
			node.children = append(node.children, child2)
			child2.insert(key, value)
			return
		}
		node = child
	}
}

type ExecTraces struct {
	sync.RWMutex
	root *Node
}

func NewExecTraces() *ExecTraces {
	et := &ExecTraces{}
	et.root = &Node{}
	return et
}

func (et *ExecTraces) Insert(prefix []uint64, value string) error {
	et.Lock()
	defer et.Unlock()

	et.root.insert(prefix, &value)
	return nil
}

func (et *ExecTraces) Query(prefix []uint64) (found bool, length int) {
	et.RLock()
	defer et.RUnlock()

	length = 0
	found = false

	node := et.root
	if node.prefix == nil {
		return
	}

	for {
		common := node.longestCommonPrefixLen(prefix)
		length += common

		prefix = prefix[common:]
		if len(node.prefix) == common && len(prefix) > 0 {
			child := node.next(prefix[0])
			if child == nil {
				return
			}
			node = child
		} else {
			if len(prefix) == 0 {
				found = true
				return
			}
			return
		}
	}
}
