package main

import (
	"fmt"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

func main() {
	fmt.Println("modules!")
	x, y, z := bananaphone.GetModuleLoadedOrder(0)
	fmt.Printf("%x, %x %+v\n", x, y, z)
	x, y, z = bananaphone.GetModuleLoadedOrder(1)
	fmt.Printf("%x, %x %+v\n", x, y, z)
	x, y, z = bananaphone.GetModuleLoadedOrder(2)
	fmt.Printf("%x, %x %+v\n", x, y, z)

	fmt.Println("end modules!")
	fmt.Println(bananaphone.InMemLoads())

	fmt.Printf("%+v\n", bananaphone.GetModuleLoadedOrderPtr(1))
	fmt.Println("end modules!")
}
