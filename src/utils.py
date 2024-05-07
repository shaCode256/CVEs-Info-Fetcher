import os


def save_bytes_to_file(data_bytes, filename):
    """

    :param data_bytes:
    :param filename:
    """
    with open(filename, 'wb') as file:
        file.write(data_bytes)

def clean_system(visualizations):
    """

    :param visualizations:
    """
    # Remove temp graphs pictures
    if visualizations:
        for plot_path in visualizations:
            os.remove(plot_path)
