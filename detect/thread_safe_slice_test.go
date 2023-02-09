package detect

import (
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

func TestNewThreadSafeSlice(t *testing.T) {
	type args struct {
		slice []int
	}
	tests := []struct {
		name string
		args args
		want ThreadSafeSlice[int]
	}{
		{name: "create_empty",
			args: args{slice: []int{}},
			want: ThreadSafeSlice[int]{
				mutex: sync.Mutex{},
				slice: []int{},
			},
		},
		{name: "create_from_slice",
			args: args{slice: []int{1, 2, 3, 4}},
			want: ThreadSafeSlice[int]{
				mutex: sync.Mutex{},
				slice: []int{1, 2, 3, 4},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewThreadSafeSlice(tt.args.slice), "NewThreadSafeSlice(%v)", tt.args.slice)
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
			tslice.append(tt.args.item)
			assert.Equalf(t, tt.want, tslice.slice, "")
		})
	}
}

func TestThreadSafeSlice_pop(t *testing.T) {
	type fields struct {
		slice []int
	}

	type wants struct {
		item        int
		sliceRemain []int
	}

	tests := []struct {
		name   string
		fields fields
		want   wants
	}{
		{name: "test_pop",
			fields: fields{slice: []int{5, 4, 3}},
			want: wants{
				item:        5,
				sliceRemain: []int{4, 3},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tslice := NewThreadSafeSlice(tt.fields.slice)
			assert.Equalf(t, tt.want, wants{
				item:        tslice.pop(),
				sliceRemain: tslice.slice,
			}, "pop()")
		})
	}
}
