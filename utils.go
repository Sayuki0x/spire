package main

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
