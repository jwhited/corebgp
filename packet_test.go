package corebgp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCapability_Equal(t *testing.T) {
	type fields struct {
		Code  uint8
		Value []byte
	}
	type args struct {
		d Capability
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "equal",
			fields: fields{
				Code:  1,
				Value: []byte{1},
			},
			args: args{
				d: Capability{
					Code:  1,
					Value: []byte{1},
				},
			},
			want: true,
		},
		{
			name: "unequal code",
			fields: fields{
				Code:  1,
				Value: []byte{1},
			},
			args: args{
				d: Capability{
					Code:  2,
					Value: []byte{1},
				},
			},
			want: false,
		},
		{
			name: "unequal value",
			fields: fields{
				Code:  1,
				Value: []byte{1},
			},
			args: args{
				d: Capability{
					Code:  1,
					Value: []byte{2},
				},
			},
			want: false,
		},
		{
			name: "equal nil and empty value",
			fields: fields{
				Code:  1,
				Value: []byte{},
			},
			args: args{
				d: Capability{
					Code:  1,
					Value: nil,
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Capability{
				Code:  tt.fields.Code,
				Value: tt.fields.Value,
			}
			assert.Equalf(t, tt.want, c.Equal(tt.args.d), "Equal(%v)", tt.args.d)
		})
	}
}
