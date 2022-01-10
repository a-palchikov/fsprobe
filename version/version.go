package version

var (
	BuildGitCommit string
	BuildGitBranch string
	BuildTime      string
	BuildGoVersion string
)

type Version struct {
	GitCommit      string `json:"commit"`
	GitBranch      string `json:"branch"`
	BuildTime      string `json:"time"`
	BuildGoVersion string `json:"goversion"`
}

func Get() Version {
	return Version{
		GitCommit:      BuildGitCommit,
		GitBranch:      BuildGitBranch,
		BuildTime:      BuildTime,
		BuildGoVersion: BuildGoVersion,
	}
}
