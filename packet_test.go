package corebgp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestDecodeAddPathTuples(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []AddPathTuple
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid tuples",
			args: args{
				b: []byte{
					0x00, 0x01, // afi
					0x01,       // safi
					0x02,       // tx
					0x00, 0x02, // afi
					0x01,       // safi
					0x01,       // tx
					0x00, 0x03, // afi
					0x01, // safi
					0x03, // tx
				},
			},
			want: []AddPathTuple{
				{
					AFI:  1,
					SAFI: 1,
					Tx:   true,
				},
				{
					AFI:  2,
					SAFI: 1,
					Rx:   true,
				},
				{
					AFI:  3,
					SAFI: 1,
					Tx:   true,
					Rx:   true,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid tuple on tail",
			args: args{
				b: []byte{
					0x00, 0x01, // afi
					0x01,       // safi
					0x02,       // tx
					0x00, 0x02, // afi
					0x01,       // safi
					0x01,       // tx
					0x00, 0x03, // afi
					0x01,       // safi
					0x03,       // tx
					0x00, 0x03, // afi
					0x01, // safi
					// no direction octet
				},
			},
			want:    nil,
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeAddPathTuples(tt.args.b)
			if !tt.wantErr(t, err, fmt.Sprintf("DecodeAddPathTuples(%v)", tt.args.b)) {
				return
			}
			assert.Equalf(t, tt.want, got, "DecodeAddPathTuples(%v)", tt.args.b)
		})
	}
}
