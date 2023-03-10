package detect

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewThreadSafeSlice(t *testing.T) {
	type args struct {
		slice []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{name: "create_empty",
			args: args{slice: []int{}},
			want: []int{},
		},
		{name: "create_from_slice",
			args: args{slice: []int{1, 2, 3, 4}},
			want: []int{1, 2, 3, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tts := NewThreadSafeSlice(tt.args.slice)
			assert.Equalf(t, tt.want, tts.slice, "NewThreadSafeSlice(%v)", tt.args.slice)
		})
	}
}

func TestThreadSafeSlice_append(t *testing.T) {
	type fields struct {
		slice []int
	}
	type args struct {
		item int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []int
	}{
		{name: "append_int",
			fields: fields{
				slice: []int{},
			},
			args: args{item: 1},
			want: []int{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tslice := NewThreadSafeSlice(tt.fields.slice)
			tslice.Append(tt.args.item)
			assert.Equalf(t, tt.want, tslice.slice, "")
		})
	}
}

func TestThreadSafeSlice_pop(t *testing.T) {
	type linkedList struct {
		head int
		tail *linkedList
	}

	type fields struct {
		slice []linkedList
	}

	type wants struct {
		item        linkedList
		success     bool
		sliceRemain []linkedList
	}

	tests := []struct {
		name   string
		fields fields
		want   wants
	}{
		{name: "test_pop",
			fields: fields{slice: []linkedList{
				{
					head: 1,
					tail: nil,
				},
				{
					head: 2,
					tail: nil,
				},
			},
			},
			want: wants{
				item:        linkedList{head: 1, tail: nil},
				success:     true,
				sliceRemain: []linkedList{{head: 2, tail: nil}},
			},
		},
		{name: "test_pop_empty",
			fields: fields{slice: []linkedList{}},
			want: wants{
				item:        linkedList{},
				success:     false,
				sliceRemain: []linkedList{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tslice := NewThreadSafeSlice(tt.fields.slice)
			item, success := tslice.Pop()
			assert.Equalf(t, tt.want, wants{
				item:        item,
				success:     success,
				sliceRemain: tslice.slice,
			}, "Pop()")
		})
	}
}
