module.exports.resolveModularContent = function(video){
    if (video.videoHost.value.find(item => item.codename === "vimeo")) {

        return `<iframe class="hosted-video__wrapper"
                    src="https://player.vimeo.com/video/${video.videoId.value}?title =0&byline =0&portrait =0"
                    width="640"
                    height="360"
                    frameborder="0"
                    webkitallowfullscreen
                    mozallowfullscreen
                    allowfullscreen
                    >
            </iframe>`;
    }
    else if (video.videoHost.value.find(item => item.codename === "youtube")) {

        return `<iframe class="hosted-video__wrapper"
                    width="560"
                    height="315"
                    src="https://www.youtube.com/embed/${video.videoId.value}"
                    frameborder="0"
                    allowfullscreen
                    >
            </iframe>`;
    }
    
    return "";  
}