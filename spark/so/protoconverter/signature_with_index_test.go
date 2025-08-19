package protoconverter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSparkSignatureWithIndexFromTokenProto(t *testing.T) {
	tests := []struct {
		name  string
		input *tokenpb.SignatureWithIndex
		want  *sparkpb.SignatureWithIndex
	}{
		{
			name:  "normal conversion",
			input: &tokenpb.SignatureWithIndex{Signature: []byte{1, 2, 3, 4}, InputIndex: 5},
			want:  &sparkpb.SignatureWithIndex{Signature: []byte{1, 2, 3, 4}, InputIndex: 5},
		},
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SparkSignatureWithIndexFromTokenProto(tt.input)
			if diff := cmp.Diff(tt.want, result, protocmp.Transform()); diff != "" {
				t.Errorf("SparkSignatureWithIndexFromTokenProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
