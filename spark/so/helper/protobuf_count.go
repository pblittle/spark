package helper

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func countMessageType(msg protoreflect.Message, targetMessageName protoreflect.FullName) int {
	count := 0

	// Check if current message is the target type
	if msg.Descriptor().FullName() == targetMessageName {
		count++
	}

	// Iterate through all fields of the current message
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			// Handle map fields
			v.Map().Range(func(mk protoreflect.MapKey, mv protoreflect.Value) bool {
				if fd.MapValue().Kind() == protoreflect.MessageKind {
					count += countMessageType(mv.Message(), targetMessageName)
				}
				return true
			})
		case fd.IsList():
			// Handle repeated fields
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				item := list.Get(i)
				if fd.Kind() == protoreflect.MessageKind {
					count += countMessageType(item.Message(), targetMessageName)
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			// Handle single message fields
			count += countMessageType(v.Message(), targetMessageName)
		}
		return true
	})

	return count
}

// Helper function that works with proto.Message interface
func CountMessageTypeInProto(msg proto.Message, targetMessageName string) int {
	return countMessageType(msg.ProtoReflect(), protoreflect.FullName(targetMessageName))
}
