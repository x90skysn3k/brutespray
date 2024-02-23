package banner

import (
	"math/rand"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

func color_banner(text string) string {

	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)

	startColor := pterm.NewRGB(uint8(random.Intn(256)), uint8(random.Intn(256)), uint8(random.Intn(256)))
	firstPoint := pterm.NewRGB(uint8(random.Intn(256)), uint8(random.Intn(256)), uint8(random.Intn(256)))

	//startColor := pterm.NewRGB(0, 255, 255)
	//firstPoint := pterm.NewRGB(255, 0, 255)

	str := text
	strs := strings.Split(str, "")

	var fadeInfo string

	for i := 0; i < len(str); i++ {
		if i < len(strs) {
			fadeInfo += startColor.Fade(0, float32(len(str)), float32(i%(len(str)/2)), firstPoint).Sprint(strs[i])
		}
	}

	return fadeInfo
}

func Banner(version string, banner_flag bool) {

	banner := `
                              #@                           @/
                           @@@                               @@@
                        %@@@                                   @@@.
                      @@@@@                                     @@@@%
                     @@@@@                                       @@@@@
                    @@@@@@@                  @                  @@@@@@@
                    @(@@@@@@@%            @@@@@@@            &@@@@@@@@@
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     @@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@
                       @@@( @@@@@#@@@@@@@@@*@@@,@@@@@@@@@@@@@@@  @@@
                           @@@@@@ .@@@/@@@@@@@@@@@@@/@@@@ @@@@@@
                                  @@@   @@@@@@@@@@@   @@@
                                 @@@@*  ,@@@@@@@@@(  ,@@@@
                                 @@@@@@@@@@@@@@@@@@@@@@@@@
                                  @@@.@@@@@@@@@@@@@@@ @@@
                                    @@@@@@ @@@@@ @@@@@@
                                       @@@@@@@@@@@@@
                                       @@   @@@   @@
                                       @@ @@@@@@@ @@
                                         @@% @  @@

`
	banner2 := `
██████╗  ██████╗  ██╗   ██╗ ████████╗ ███████╗ ███████╗ ██████╗  ██████╗   █████╗  ██╗   ██╗ 
██╔══██╗ ██╔══██╗ ██║   ██║ ╚══██╔══╝ ██╔════╝ ██╔════╝ ██╔══██╗ ██╔══██╗ ██╔══██╗ ╚██╗ ██╔╝ 
██████╔╝ ██████╔╝ ██║   ██║    ██║    █████╗   ███████╗ ██████╔╝ ██████╔╝ ███████║  ╚████╔╝  
██╔══██╗ ██╔══██╗ ██║   ██║    ██║    ██╔══╝   ╚════██║ ██╔═══╝  ██╔══██╗ ██╔══██║   ╚██╔╝   
██████╔╝ ██║  ██║ ╚██████╔╝    ██║    ███████╗ ███████║ ██║      ██║  ██║ ██║  ██║    ██║    
╚═════╝  ╚═╝  ╚═╝  ╚═════╝     ╚═╝    ╚══════╝ ╚══════╝ ╚═╝      ╚═╝  ╚═╝ ╚═╝  ╚═╝    ╚═╝    ` + "\n"
	quiet_banner :=
		`Brutespray ` + version + `
Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail
Inspired by: Leon Johnson/@sho-luv`
	//ascii art by: Cara Pearson
	if !banner_flag {
		horns := color_banner(banner)
		pterm.Println(horns)
		brutespray := color_banner(banner2)
		pterm.Println(brutespray)
	}

	pterm.FgRed.Println(quiet_banner)

}
