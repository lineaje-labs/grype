package lineaje

import "encoding/json"

// Inspired by https://github.com/hashicorp/go-set

type void struct{}

type Set[T comparable] struct {
	items map[T]void
}

func NewSet[T comparable](item ...T) *Set[T] {
	x := &Set[T]{
		items: make(map[T]void),
	}
	x.InsertAll(item)
	return x
}

func FromList[T comparable](items []T) *Set[T] {
	s := NewSet[T]()
	s.InsertAll(items)
	return s
}

func FromSet[T comparable](set *Set[T]) *Set[T] {
	s := NewSet[T]()
	s.InsertSet(set)
	return s
}

func (s *Set[T]) Insert(item T) bool {
	if _, exists := s.items[item]; exists {
		return false
	}
	s.items[item] = void{}
	return true
}

func (s *Set[T]) InsertAll(items []T) bool {
	modified := false
	for _, item := range items {
		if s.Insert(item) {
			modified = true
		}
	}
	return modified
}

func (s *Set[T]) InsertSet(set *Set[T]) bool {
	modified := false
	for item := range set.items {
		if s.Insert(item) {
			modified = true
		}
	}
	return modified
}

func (s *Set[T]) Remove(item T) bool {
	if _, exists := s.items[item]; !exists {
		return false
	}
	delete(s.items, item)
	return true
}

func (s *Set[T]) Clear() {
	for item := range s.items {
		delete(s.items, item)
	}
}

func (s *Set[T]) Contains(item T) bool {
	_, exists := s.items[item]
	return exists
}

func (s *Set[T]) Size() int {
	return len(s.items)
}

func (s *Set[T]) IsEmpty() bool {
	return len(s.items) == 0
}

func (s *Set[T]) List() []T {
	result := make([]T, 0, s.Size())
	for item := range s.items {
		result = append(result, item)
	}
	return result
}

func (s *Set[T]) Items() map[T]void {
	return s.items
}

// MarshalJSON implements the json.Marshaller interface.
func (s *Set[T]) MarshalJSON() ([]byte, error) {
	setList := make([]T, 0)
	for item := range s.items {
		setList = append(setList, item)
	}
	return json.Marshal(setList)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *Set[T]) UnmarshalJSON(data []byte) error {
	slice := make([]T, 0)
	err := json.Unmarshal(data, &slice)
	if err != nil {
		return err
	}
	s.items = make(map[T]void)
	for _, item := range slice {
		s.Insert(item)
	}
	return nil
}
