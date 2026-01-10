package helper

import "gorm.io/gen/field"

func Sort(orderCol field.OrderExpr, direction string) field.Expr {
	if direction == "desc" {
		return orderCol.Desc()
	}
	return orderCol.Asc()
}
